// SCOUT:TESTS:BEGIN
#[cfg(test)]
mod scout_reachability {
    use super::*;

    /// setup() must build a world in which the whole value flow is live. If this regresses,
    /// every coverage number below it is measuring a broken harness rather than the program.
    #[test]
    fn t_core_value_flow_is_reachable() {
        let mut f = OnreappFixture::setup();
        assert!(f.action_take_offer(10_000_000), "take_offer");
        assert!(f.action_take_offer_permissionless(5_000_000), "take_offer_permissionless");
        assert!(f.action_create_redemption_request(1_000_000), "create_redemption_request");
        assert!(f.action_fulfill_redemption_request(), "fulfill_redemption_request");
        assert!(f.action_create_redemption_request(2_000_001), "create_redemption_request #2");
        assert!(f.action_cancel_redemption_request(), "cancel_redemption_request");
    }

    /// P-0003's regression, preserved deterministically now that its block is retired.
    ///
    /// `RedemptionOffer.requested_redemptions` must equal the sum of `amount` over the requests
    /// that still exist, across every path that retires one. P-0003 survived 3.4M+ fuzz
    /// executions; this pins the same statement so retiring its block does not silently drop it.
    ///
    /// Uses the plain-SPL forward offer, where deposit == credit, so any drift here is the
    /// program's own accounting rather than a transfer fee (that is P-0008's subject).
    #[test]
    fn t_p0003_requested_redemptions_tracks_open_requests() {
        let mut f = OnreappFixture::setup();

        fn check(f: &OnreappFixture, label: &str) -> u128 {
            let recorded = f
                .onchain_requested_redemptions()
                .expect("requested_redemptions readable");
            let summed: u128 = f
                .open_requests_of(&f.redemption_offer_pda)
                .expect("requests enumerable")
                .iter()
                .map(|(_, _, a)| *a as u128)
                .sum();
            assert_eq!(recorded, summed, "P-0003 drift after {}", label);
            recorded
        }

        assert_eq!(check(&f, "setup"), 0);

        assert!(f.action_create_redemption_request(1_000_000), "create #1");
        assert_eq!(check(&f, "create #1"), 1_000_000);

        assert!(f.action_create_redemption_request(2_500_000), "create #2");
        assert_eq!(check(&f, "create #2"), 3_500_000);

        // Fulfilment retires a request and must decrement by exactly what it locked.
        assert!(f.action_fulfill_redemption_request(), "fulfil oldest");
        assert_eq!(check(&f, "fulfil"), 2_500_000);

        // Cancellation is the other retirement path.
        assert!(f.action_cancel_redemption_request(), "cancel remaining");
        assert_eq!(check(&f, "cancel"), 0);
    }

    /// The transfer-fee fixture must actually be fee-bearing, and the program must actually
    /// accept it on the redemption path. If either half regresses, every campaign below reads
    /// clean for a reason that has nothing to do with the program.
    ///
    /// Positive control included: the OFFER path must still REFUSE the same mint, which is what
    /// proves the fee is live rather than that the harness built an ordinary mint.
    #[test]
    fn t_fee_mint_fixture_is_live_and_redemption_accepts_it() {
        let mut f = OnreappFixture::setup();
        let vault = f.redemption_vault_fee();
        let before = f.tok_amt(&vault);

        assert!(f.action_scout_create_request_fee(1_000_000, 4), "create_request(fee)");

        let after = f.tok_amt(&vault);
        let claimed = f.claimed_fee();
        println!("fee vault {before} -> {after} (delta {}), claimed {claimed}", after - before);

        assert_eq!(claimed, 1_000_000, "the program must record the REQUESTED amount");
        assert!(
            after - before < claimed,
            "fixture is not fee-bearing: vault gained {} against a claim of {claimed}",
            after - before
        );
    }

    /// P-0008: on a transfer-fee token_in, the pooled redemption vault goes insolvent through
    /// ORDINARY HONEST USE, and the shortfall lands on whoever exits last.
    ///
    /// Every actor here is unprivileged and every action is one the program invites. There is no
    /// boss transaction anywhere in this sequence after setup.
    #[test]
    fn t_p0008_fee_mint_deposits_arrive_short_and_strand_the_last_redeemer() {
        let mut f = OnreappFixture::setup();
        let vault = f.redemption_vault_fee();

        // Two ordinary users each open a request for the same amount. `sel & 4` keeps the amount
        // raw so both are exactly 1_000_000; sel 4 -> user_a, sel 5 -> user_b.
        assert!(f.action_scout_create_request_fee(1_000_000, 4), "A deposits");
        assert!(f.action_scout_create_request_fee(1_000_000, 5), "B deposits");

        let held = f.tok_amt(&vault);
        let owed = f.claimed_fee();
        println!("P0008 after two honest deposits: vault={held} owed={owed} shortfall={}", owed - held);
        assert_eq!(owed, 2_000_000);
        assert_eq!(held, 1_980_000, "each deposit arrived 1% short");

        // A cancels first and is paid the amount the program RECORDED, not the amount that
        // arrived. This is a legitimate action by its own redeemer.
        assert!(f.action_scout_cancel_request_fee(0), "A cancels");

        let held = f.tok_amt(&vault);
        let owed = f.claimed_fee();
        println!("P0008 after A cancels:            vault={held} owed={owed} shortfall={}", owed - held);
        assert_eq!(owed, 1_000_000, "B's claim is untouched");
        assert_eq!(held, 980_000, "vault paid out 1_000_000 having received 990_000");

        // B now cannot get their money back. Not delayed — the vault does not hold it.
        assert!(
            !f.action_scout_cancel_request_fee(1),
            "B must NOT be able to cancel: vault holds {held} against a claim of {owed}"
        );
        assert_eq!(f.claimed_fee(), 1_000_000, "B's request is still open and still owed");
        println!("P0008 B cancel -> false; B is stranded with {} of {} recoverable", held, owed);
    }

    /// The offer path's guard is the control that proves the redemption path is missing one.
    /// Same mint, same program, same block — `take_offer` refuses it, redemption accepts it.
    #[test]
    fn t_p0008_control_offer_path_refuses_the_same_mint() {
        let mut f = OnreappFixture::setup();
        assert!(
            !f.action_scout_take_fee_offer(1_000_000),
            "take_offer MUST refuse a fee-bearing leg (token_utils.rs:374,378)"
        );
        assert!(
            f.action_scout_create_request_fee(1_000_000, 4),
            "the redemption path accepts the very same mint"
        );
    }

    /// The Ed25519 precompile must be registered in the SVM, otherwise every approval branch is
    /// silently unreachable and reads as "the program rejects approvals" instead of "the harness
    /// cannot present one". Enabled by depending on litesvm with `features = ["precompiles"]`.
    #[test]
    fn t_ed25519_precompile_is_registered() {
        let f = OnreappFixture::setup();
        let acc = f.ctx.get_account(&ED25519_PROGRAM_ID)
            .expect("Ed25519SigVerify program account must exist");
        assert!(acc.executable, "Ed25519SigVerify must be executable");
    }

    /// The approval-gated offer accepts a correctly signed, in-date, correctly-bound message and
    /// rejects the two ways it can be wrong. Covers verify_approval_message_generic's Expired and
    /// WrongUser branches, which no corpus can reach through the single-instruction actions.
    #[test]
    fn t_approval_branches() {
        let mut f = OnreappFixture::setup();
        assert!(f.action_take_offer_with_approval(1_000_000, 100_000, 0), "valid approval");
        assert!(!f.action_take_offer_with_approval(1_000_001, -100_000, 0), "expired approval");
        assert!(!f.action_take_offer_with_approval(1_000_002, 100_000, 2), "wrong-user approval");
    }

    /// The kill switch really halts the value flow, and really releases it again.
    #[test]
    fn t_kill_switch_gates_take_offer() {
        let mut f = OnreappFixture::setup();
        assert!(f.action_set_kill_switch(true), "enable kill switch");
        assert!(!f.action_take_offer(10_000_000), "take_offer must fail while killed");
        assert!(f.action_set_kill_switch(false), "disable kill switch");
        assert!(f.action_take_offer(10_000_000), "take_offer must work once released");
    }

    /// close_state really does deallocate `State`, and `action_scout_rebuild_state` is the way back.
    ///
    /// Recovery is an ACTION rather than close_state's hook because a hook region may contain only
    /// pure assignments — no calls, no conditionals. This pins both halves: that the instruction is
    /// genuinely destructive, and that the fuzzer has a route out of the state it leaves behind.
    #[test]
    fn t_close_state_is_destructive_and_recoverable() {
        let mut f = OnreappFixture::setup();
        assert!(f.state_exists(), "State must exist after setup");

        assert!(f.action_close_state(), "close_state");
        assert!(!f.state_exists(), "close_state must really deallocate State");
        assert!(!f.action_take_offer(10_000_000), "no world means no take_offer");

        assert!(f.action_scout_rebuild_state(), "rebuild must succeed while State is missing");
        assert!(f.state_exists(), "State must be back");
        assert!(f.action_take_offer(10_000_000), "world must be usable again");

        // Idempotent: it must never silently reset a live world mid-chain.
        assert!(!f.action_scout_rebuild_state(), "rebuild must be a no-op when State exists");
    }

    /// P-0002's counterexample, as a direct reproduction rather than a fuzzer artefact.
    ///
    /// `redemption_vault_withdraw` moves an arbitrary amount out of the same token account that
    /// `create_redemption_request` locks user deposits into, consulting neither
    /// `requested_redemptions` nor any `RedemptionRequest`. Once drained, the request can be
    /// neither cancelled nor fulfilled -- both paths transfer out of that account -- so the
    /// redeemer's tokens are gone AND the request account cannot be closed.
    #[test]
    fn t_p0002_vault_drain_strands_open_requests() {
        let mut f = OnreappFixture::setup();
        let vault_onyc = f.redemption_vault_ata(&f.mint_onyc);
        let amount: u64 = 5_000_000_001; // odd -> the vault-op actions select the ONyc mint

        assert!(f.action_create_redemption_request(amount), "create_redemption_request");
        let locked = f.ctx.token_balance(&vault_onyc);
        assert_eq!(locked, amount, "the request must have locked its tokens in the vault");
        assert_eq!(f.onchain_requested_redemptions(), Some(amount as u128));

        assert!(f.action_redemption_vault_withdraw(locked | 1), "boss drains the redemption vault");
        assert_eq!(f.ctx.token_balance(&vault_onyc), 0, "vault must now be empty");

        // The claim is still recorded, but nothing backs it.
        assert_eq!(f.onchain_requested_redemptions(), Some(amount as u128));
        assert_eq!(f.open_request_total(), Some(amount as u128));

        // Both exits are now closed.
        assert!(!f.action_cancel_redemption_request(), "cancel must fail once the vault is drained");
        assert!(!f.action_fulfill_redemption_request(), "fulfil must fail once the vault is drained");
        assert_eq!(f.open_requests().map(|v| v.len()), Some(1), "the request is stranded, not retired");
    }

    /// P-0004's counterexample as a controlled differential, not a fuzzer artefact.
    ///
    /// With the cap pinned to exactly the current supply, mint_to and take_offer are BOTH refused
    /// (they hand `state.max_supply` to `mint_tokens`), while fulfilling a redemption whose payout
    /// leg is the program-controlled mint succeeds and mints straight past it — because
    /// `fulfill_redemption_request.rs:274` hands `mint_tokens` a hard-coded 0 instead.
    #[test]
    fn t_p0004_redemption_fulfilment_bypasses_max_supply() {
        let mut f = OnreappFixture::setup();
        assert!(f.action_scout_configure_max_supply(0), "configure_max_supply with zero headroom");
        let cap = {
            let d = f.ctx.account_data(&f.state_pda).unwrap();
            u64::from_le_bytes(d[SCOUT_STATE_MAX_SUPPLY_OFFSET..SCOUT_STATE_MAX_SUPPLY_END]
                .try_into().unwrap())
        };
        let before = f.onyc_supply().expect("onyc supply");
        assert_eq!(cap, before, "cap must start exactly at the current supply");

        // Controls: the two callers that pass state.max_supply refuse to mint even one unit.
        assert!(!f.action_mint_to(1), "mint_to must respect the cap");
        assert!(!f.action_take_offer(10_000_000), "take_offer must respect the cap");
        assert_eq!(f.onyc_supply(), Some(before), "no control path may move the supply");

        // The redemption payout path is not bound by the same cap.
        assert!(f.action_scout_create_request_rev(1_000_000, 0), "create reverse redemption request");
        assert!(f.action_scout_fulfill_rev(), "fulfil mints ONyc");

        let after = f.onyc_supply().expect("onyc supply");
        assert!(after > cap, "supply {after} must have passed the cap {cap}");
    }

    /// P-0005: `make_offer` accepts an offer whose two legs are the SAME mint, and taking it
    /// below par mints the taker free tokens.
    ///
    /// 1e9 ONyc in -> 2e9 ONyc out at a price of 0.5, with the supply inflating by the difference.
    /// No constraint anywhere in the program relates token_in_mint to token_out_mint.
    #[test]
    fn t_p0005_same_mint_offer_mints_free_tokens() {
        let mut f = OnreappFixture::setup();
        // fee_basis_points = 3 selects make_offer_pair variant 3 = (onyc, onyc). The program
        // accepts it: nothing relates the two mint arguments.
        assert!(f.action_make_offer(3, false, false), "make_offer accepts token_in == token_out");
        assert!(f.action_scout_price_same_mint_offer(500_000_000), "price it at 0.5");

        let user = f.pick_user(0).pubkey();
        let uata = scout_ata(&user, &f.mint_onyc, &SPL_TOKEN_ID);
        let held_before = f.ctx.token_balance(&uata);
        let supply_before = f.onyc_supply().expect("supply");

        assert!(f.action_scout_take_same_mint_offer(1_000_000_000, 4), "take the self-referential offer");

        let held_after = f.ctx.token_balance(&uata);
        let supply_after = f.onyc_supply().expect("supply");
        // Arithmetic, with the offer's 3 bp fee (fee_basis_points = 3 also selected the pair):
        //   fee  = ceil(1e9 * 3 / 10_000)                    =   300_000  -> boss
        //   net  = 1e9 - fee                                 = 999_700_000 -> burned
        //   out  = net * 10^(9+9) / (0.5e9 * 10^9)           = 1_999_400_000 -> minted to taker
        //   taker delta = out - 1e9                          =   999_400_000
        //   supply delta = out - net                         =   999_700_000
        assert!(held_after > held_before,
            "taker must have gained: {held_before} -> {held_after}");
        assert_eq!(held_after - held_before, 999_400_000,
            "taker paid 1e9 of a token and received 1.9994e9 of the SAME token");
        assert_eq!(supply_after - supply_before, 999_700_000,
            "the gain is newly minted supply (taker gain + boss fee), not a transfer from anyone");
    }

    /// LEAD (low): an Anchor CONSTRAINT calls `mint.mint_authority.unwrap()`, so a mint with no
    /// authority makes the program PANIC rather than return its declared error code.
    #[test]
    fn t_lead_unwrap_panics_on_authorityless_mint() {
        let mut f = OnreappFixture::setup();
        let boss = f.boss.insecure_clone();
        let dead = f.ctx.create_mint().pubkey(Keypair::new().pubkey())
            .decimals(6).supply(0).create().unwrap();  // mint_authority = COption::None
        let out = f.ctx.program(f.program_id)
            .call(instruction::TransferMintAuthorityToProgram {})
            .accounts(accounts::TransferMintAuthorityToProgram {
                boss: boss.pubkey(), state: f.state_pda, mint: dead,
                mint_authority: f.mint_authority_pda, token_program: SPL_TOKEN_ID })
            .signers(&[&boss]).send().expect("tx submitted");
        assert!(!out.is_success(), "must not succeed");
        let logs = out.logs().join("\n");
        assert!(logs.contains("SBF program panicked"),
            "expected a panic, not a clean error. logs:\n{logs}");
        assert!(logs.contains("COption::unwrap()"), "logs:\n{logs}");
    }

    /// LEAD (low): `create_redemption_request` has `payer = redeemer` but
    /// `cancel_redemption_request` has `close = redemption_admin`, so the request account's rent
    /// moves from the user to the admin on every create/cancel cycle. `cancel` may be signed by
    /// the redemption_admin or the boss, so they can harvest it from any pending request.
    #[test]
    fn t_lead_cancel_rent_goes_to_admin_not_payer() {
        let mut f = OnreappFixture::setup();
        let user = f.pick_user(0).pubkey();
        let admin = f.redemption_admin.pubkey();
        let lam = |f: &OnreappFixture, k: &Pubkey| f.ctx.get_account(k).map(|a| a.lamports).unwrap_or(0);

        let (u0, a0) = (lam(&f, &user), lam(&f, &admin));
        assert!(f.action_create_redemption_request(1_000_000), "create");
        assert!(f.action_cancel_redemption_request(), "cancel");
        let (u1, a1) = (lam(&f, &user), lam(&f, &admin));

        let user_delta = u0 - u1;
        let admin_delta = a1 - a0;
        assert!(user_delta > 0, "the redeemer paid the rent");
        assert_eq!(user_delta, admin_delta,
            "and the admin received exactly it back on cancel ({user_delta} lamports)");
    }

    /// P-0006: `update_offer_fee` bounds against the WRONG constant, so the boss can raise an
    /// offer's fee to 99.99% — far past the 10% ceiling every other fee path enforces.
    ///
    /// The control is the important half: the same value is REJECTED by make_offer and by both
    /// redemption fee paths, so this is one writer using MAX_BASIS_POINTS where its three siblings
    /// use MAX_ALLOWED_FEE_BPS, not a difference of opinion about what the ceiling is.
    #[test]
    fn t_p0006_update_offer_fee_bypasses_the_fee_ceiling() {
        let mut f = OnreappFixture::setup();
        let offer = f.offer_pda;
        let fee_of = |f: &OnreappFixture, o: &Pubkey| -> u16 {
            let d = f.ctx.account_data(o).unwrap();
            u16::from_le_bytes(d[SCOUT_OFFER_FEE_OFFSET..SCOUT_OFFER_FEE_END].try_into().unwrap())
        };
        assert_eq!(fee_of(&f, &offer), 100, "setup created it at 1%");

        // Control 1: make_offer refuses anything above MAX_ALLOWED_FEE_BPS.
        assert!(!f.action_make_offer(1001, false, false), "make_offer must refuse 1001 bp");
        // Control 2: the redemption fee path refuses it too.
        assert!(!f.action_update_redemption_offer_fee(1001), "redemption fee must refuse 1001 bp");
        assert!(f.action_update_redemption_offer_fee(1000), "...but accepts exactly 1000 bp");

        // The gap: update_offer_fee accepts 99.99%.
        assert!(f.action_update_offer_fee(9999), "update_offer_fee accepts 9999 bp");
        assert_eq!(fee_of(&f, &offer), 9999, "the offer now charges 99.99%");
    }

    // ---- escalation-chaining pass 2: helpers ---------------------------------------------------
    fn vault_onyc(f: &OnreappFixture) -> u64 { f.ctx.token_balance(&f.redemption_vault_onyc) }
    fn is_killed(f: &OnreappFixture) -> bool {
        f.ctx.account_data(&f.state_pda).map(|d| d[72] != 0).unwrap_or(false)
    }

    /// CHAIN C1 = P-0002 ∧ amplifier #6 (gate removal).
    /// The kill switch closes the user exits but not the boss's drain.
    #[test]
    fn c1_killswitch_closes_exits_but_not_the_drain() {
        let mut f = OnreappFixture::setup();
        let amount: u64 = 5_000_000_001; // odd -> vault ops select the ONyc mint
        assert!(f.action_create_redemption_request(amount), "user locks collateral");
        let locked = vault_onyc(&f);
        assert_eq!(locked, amount);

        assert!(f.action_set_kill_switch(true), "boss engages the emergency stop");
        assert!(is_killed(&f));

        // Every user exit is now shut.
        println!("C1 killed: cancel  -> {}", f.action_cancel_redemption_request());
        println!("C1 killed: fulfil  -> {}", f.action_fulfill_redemption_request());
        println!("C1 killed: create  -> {}", f.action_create_redemption_request(1_000_000_001));
        // The drain is not.
        let drained = f.action_redemption_vault_withdraw(locked | 1);
        println!("C1 killed: vault_withdraw -> {drained}");
        println!("C1 vault {locked} -> {}", vault_onyc(&f));
    }

    /// CHAIN C2 = P-0006 ∧ amplifier #4/#10 (snapshot staleness at the config extreme).
    /// take_offer has no minimum-output parameter, so a fee raised to 100% between quote and
    /// execution confiscates the taker's entire input for zero output.
    #[test]
    fn c2_hundred_percent_fee_confiscates_the_taker() {
        let mut f = OnreappFixture::setup();
        let user = f.pick_user(0).pubkey();
        let u_in = scout_ata(&user, &f.mint_usdc, &SPL_TOKEN_ID);
        let u_out = scout_ata(&user, &f.mint_onyc, &SPL_TOKEN_ID);
        let boss_in = scout_ata(&f.boss.pubkey(), &f.mint_usdc, &SPL_TOKEN_ID);

        println!("C2 update_offer_fee(10000) -> {}", f.action_update_offer_fee(10_000));
        let (a0, b0, c0) = (f.ctx.token_balance(&u_in), f.ctx.token_balance(&u_out), f.ctx.token_balance(&boss_in));
        let ok = f.action_take_offer(1_000_000_000);
        let (a1, b1, c1) = (f.ctx.token_balance(&u_in), f.ctx.token_balance(&u_out), f.ctx.token_balance(&boss_in));
        println!("C2 take_offer(1e9) -> {ok}");
        println!("C2 user token_in  {a0} -> {a1}   (paid {})", a0 as i128 - a1 as i128);
        println!("C2 user token_out {b0} -> {b1}   (received {})", b1 as i128 - b0 as i128);
        println!("C2 boss token_in  {c0} -> {c1}   (gained {})", c1 as i128 - c0 as i128);
    }

    /// CHAIN C3 = P-0005 ∧ amplifier #10 (config extreme).
    /// The MINIMUM legal price is 1 (add_offer_vector only requires base_price > 0), so a
    /// self-referential offer multiplies the taker's balance by 1e9 per call, not 2x.
    #[test]
    fn c3_same_mint_at_minimum_legal_price() {
        let mut f = OnreappFixture::setup();
        assert!(f.action_make_offer(3, false, false), "same-mint offer (variant 3)");
        assert!(f.action_scout_price_same_mint_offer(1), "base_price = 1, the minimum legal value");
        let user = f.pick_user(4).pubkey();
        let uata = scout_ata(&user, &f.mint_onyc, &SPL_TOKEN_ID);
        let (before, sup0) = (f.ctx.token_balance(&uata), f.onyc_supply().unwrap());
        let ok = f.action_scout_take_same_mint_offer(1_000, 4);
        let (after, sup1) = (f.ctx.token_balance(&uata), f.onyc_supply().unwrap());
        println!("C3 take(1000) -> {ok}");
        println!("C3 user onyc {before} -> {after}  (x{})", if before>0 {after/before} else {0});
        println!("C3 supply    {sup0} -> {sup1}  (minted {})", sup1 as i128 - sup0 as i128);
    }

    /// CHAIN C7 = amplifier #4 (snapshot staleness) ALONE — no other finding required.
    ///
    /// `add_offer_vector` accepts `start_time = max(now, base_time)`, so a new vector priced by the
    /// boss becomes active IMMEDIATELY. Combined with take_offer having no minimum-output
    /// parameter, the boss can move the price under an in-flight take and confiscate the input.
    /// This does NOT depend on P-0006 and survives fixing it.
    #[test]
    fn c7_price_can_be_moved_under_an_inflight_take() {
        let mut f = OnreappFixture::setup();
        let user = f.pick_user(0).pubkey();
        let u_in = scout_ata(&user, &f.mint_usdc, &SPL_TOKEN_ID);
        let u_out = scout_ata(&user, &f.mint_onyc, &SPL_TOKEN_ID);

        // Baseline: an honest take at the price the user would have quoted.
        let (a0, b0) = (f.ctx.token_balance(&u_in), f.ctx.token_balance(&u_out));
        assert!(f.action_take_offer(1_000_000_000), "honest take");
        let (a1, b1) = (f.ctx.token_balance(&u_in), f.ctx.token_balance(&u_out));
        println!("C7 honest: paid {} received {}", a0 - a1, b1 - b0);

        // Boss adds a vector that activates immediately, at an absurd but LEGAL price.
        assert!(f.action_scout_advance_time(3_600), "move past the existing vector");
        let now = scout_now(&f.ctx);
        let ok = f.action_add_offer_vector(now, u64::MAX / 4, 0, 3_600);
        println!("C7 add_offer_vector(base_price = u64::MAX/4) -> {ok}");

        // Same call, same arguments, from the user's point of view.
        let (a2, b2) = (f.ctx.token_balance(&u_in), f.ctx.token_balance(&u_out));
        let took = f.action_take_offer(1_000_000_000);
        let (a3, b3) = (f.ctx.token_balance(&u_in), f.ctx.token_balance(&u_out));
        println!("C7 after repricing: take -> {took}");
        println!("C7   paid {}  received {}", a2 as i128 - a3 as i128, b3 as i128 - b2 as i128);
    }

    /// CHAIN C4 = P-0004 ∧ amplifier #1 (constant collision).
    /// max_supply == 0 is overloaded to mean "no cap", so a boss setting 0 to HALT issuance
    /// actually removes the cap entirely.
    #[test]
    fn c4_max_supply_zero_means_unlimited_not_frozen() {
        let mut f = OnreappFixture::setup();
        // First set a real cap so minting is refused...
        assert!(f.action_scout_configure_max_supply(0), "cap at current supply");
        println!("C4 with cap == supply: mint_to(1) -> {}", f.action_mint_to(1));
        // ...then "freeze" it by setting the cap to zero.
        let boss = f.boss.insecure_clone();
        let ok = f.ctx.program(f.program_id)
            .call(instruction::ConfigureMaxSupply { max_supply: 0 })
            .accounts(accounts::ConfigureMaxSupply { state: f.state_pda, boss: boss.pubkey() })
            .signers(&[&boss]).send().map(|o| o.is_success()).unwrap_or(false);
        println!("C4 configure_max_supply(0) -> {ok}");
        let s0 = f.onyc_supply().unwrap();
        println!("C4 with cap == 0:      mint_to(1e9) -> {}", f.action_mint_to(1_000_000_000));
        println!("C4 supply {s0} -> {}", f.onyc_supply().unwrap());
    }

    /// Prove the P-0007 subject is actually constructible: TWO redemption offers whose token_in is
    /// ONyc, both funding the SAME vault token account. Without this the property degenerates into
    /// P-0002 and is silently dead.
    #[test]
    fn p7_two_offers_share_one_vault() {
        let mut f = OnreappFixture::setup();
        let vault = f.redemption_vault_onyc;
        assert!(f.action_make_offer(0, false, false), "offer play->onyc (pair variant 0)");
        assert!(f.action_make_redemption_offer(25), "redemption offer onyc->play");

        let v0 = f.ctx.token_balance(&vault);
        assert!(f.action_create_redemption_request(1_000_000), "request on setup's onyc->usdc offer");
        let v1 = f.ctx.token_balance(&vault);
        assert!(f.action_scout_create_request_play(2_000_000, 0), "request on the onyc->play offer");
        let v2 = f.ctx.token_balance(&vault);

        println!("P7 vault {v0} -> {v1} -> {v2}");
        println!("P7 registry entries: {}", f.scout_p7_next);
        assert!(v1 > v0 && v2 > v1, "both offers must fund the SAME vault account");
        assert_eq!(f.scout_p7_next, 2, "both requests registered");
    }

    /// C5 decisive experiment: does one offer's lifecycle consume ANOTHER offer's collateral?
    ///
    /// Two redemption offers share one ONyc vault account. Drive create/fulfil/cancel across both,
    /// interleaved, WITHOUT ever calling redemption_vault_withdraw (the confirmed P-0002 drain), and
    /// check the pooled bound after every step. If the pool only breaks via the drain, the
    /// cross-offer contamination hypothesis is refuted and P-0007's firings are P-0002 restated.
    #[test]
    fn c5_pool_stays_solvent_without_the_drain() {
        let mut f = OnreappFixture::setup();
        assert!(f.action_make_offer(0, false, false), "offer play->onyc");
        assert!(f.action_make_redemption_offer(25), "second onyc-denominated redemption offer");

        let vault = f.redemption_vault_onyc;
        let claimed = |f: &OnreappFixture| -> u64 {
            let mut t = 0u64;
            for pda in f.scout_p7_reqs {
                if pda == Pubkey::default() { continue; }
                if let Ok(d) = f.ctx.account_data(&pda) {
                    if d.len() >= SCOUT_REQ_MIN_LEN {
                        t = t.saturating_add(u64::from_le_bytes(
                            d[SCOUT_REQ_AMOUNT_OFFSET..SCOUT_REQ_MIN_LEN].try_into().unwrap()));
                    }
                }
            }
            t
        };
        let mut step = 0;
        let mut check = |f: &OnreappFixture, what: &str, step: &mut i32| {
            let held = f.ctx.token_balance(&vault);
            let c = claimed(f);
            *step += 1;
            println!("C5 {:>2}. {:<34} vault={:<14} claimed={:<14} {}",
                     step, what, held, c, if held >= c { "ok" } else { "SHORTFALL" });
            assert!(held >= c, "pool became insolvent at step {step} after {what}");
        };

        check(&f, "baseline", &mut step);
        assert!(f.action_create_redemption_request(3_000_000), "A1 on offer A");
        check(&f, "create A1", &mut step);
        assert!(f.action_scout_create_request_play(5_000_000, 0), "B1 on offer B");
        check(&f, "create B1", &mut step);
        assert!(f.action_create_redemption_request(7_000_001), "A2 on offer A");
        check(&f, "create A2", &mut step);
        assert!(f.action_scout_create_request_play(11_000_000, 1), "B2 on offer B");
        check(&f, "create B2", &mut step);

        // Retire them out of creation order, alternating offers.
        assert!(f.action_fulfill_redemption_request(), "fulfil A1");
        check(&f, "fulfil A1", &mut step);
        assert!(f.action_cancel_redemption_request(), "cancel A2");
        check(&f, "cancel A2", &mut step);
        // Both remaining are offer B's; drive more A traffic on top.
        assert!(f.action_create_redemption_request(2_500_000), "A3");
        check(&f, "create A3", &mut step);
        assert!(f.action_fulfill_redemption_request(), "fulfil A3");
        check(&f, "fulfil A3", &mut step);
        println!("C5 offer B's collateral still in the pool: {}", claimed(&f));
        assert!(claimed(&f) > 0, "offer B's requests must still be outstanding and covered");
    }

    /// Time must actually move, and a later vector must become addable and active once it has.
    #[test]
    fn t_clock_advances_and_new_vector_activates() {
        let mut f = OnreappFixture::setup();
        let t0 = scout_now(&f.ctx);
        assert!(f.action_scout_advance_time(7_200));
        let t1 = scout_now(&f.ctx);
        assert!(t1 > t0, "clock must advance: {t0} -> {t1}");
        assert!(f.action_add_offer_vector(t1, 2_000_000_000, 1_000_000, 600), "add later vector");
        assert!(f.action_get_nav(), "nav must price against the new vector");
    }
}
// SCOUT:TESTS:END
use crucible_test_context::*;
use crucible_fuzzer::anchor_lang::system_program;
use crucible_fuzzer::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;

// SCOUT:CHECK-CONTRACT:BEGIN sha256=c4b20795d13638b9cbca54acc8669b4394eb8494fe1116eb26b75f0b968aaf9e
// Semantic invariant checks have two modes:
//   default / SCOUT_CHECK_MODE=enforce: record a real Crucible fuzz violation;
//   SCOUT_CHECK_MODE=observe: emit nonce-bound reachability markers, never a violation.
// This exact alias is part of the trusted contract.  Generated setup and the
// macros below use `crate::`/`$crate` paths so a mutable prelude cannot replace
// Crucible's TestContext or violation/session functions with local lookalikes.
#[doc(hidden)]
extern crate crucible_test_context as __scout_crucible_test_context;

fn __scout_check_observe_mode() -> bool {
    std::env::var("SCOUT_CHECK_MODE").as_deref() == Ok("observe")
}

// Mute a property whose finding is already investigated and written up. Such a property keeps
// firing on the SAME known defect and floods the objective, hiding every other property's first
// finding behind thousands of duplicates -- observed at ~160 crashes per 25s on one target.
//
// Muting is ALWAYS announced on stderr, once per process. A silently disabled check is the exact
// false-negative trap this pipeline exists to avoid: a muted property is indistinguishable from a
// passing one unless the run says so out loud. `SCOUT_CHECK_MUTE` is also stripped from ordinary
// fuzz subprocesses alongside the other audit switches, so a stray shell variable can never
// quietly disable a check -- a caller must pass it explicitly.
fn __scout_check_announce_mutes(list: &str) {
    static MUTE_ONCE: std::sync::Once = std::sync::Once::new();
    MUTE_ONCE.call_once(|| {
        eprintln!("[SCOUT_CHECK_MUTED] {}", list);
    });
}

fn __scout_check_muted(property: &str) -> bool {
    match std::env::var("SCOUT_CHECK_MUTE") {
        Ok(list) => {
            let muted = list.split(',').any(|entry| entry.trim() == property);
            if muted {
                __scout_check_announce_mutes(&list);
            }
            muted
        }
        Err(_) => false,
    }
}

fn __scout_check_selected(property: &str) -> bool {
    if __scout_check_muted(property) {
        return false;
    }
    match std::env::var("SCOUT_CHECK_ONLY") {
        Ok(selected) => selected == property,
        Err(_) => true,
    }
}

fn __scout_check_nonce() -> Result<String, &'static str> {
    let nonce = std::env::var("SCOUT_CHECK_RUN")
        .map_err(|_| "missing or non-Unicode SCOUT_CHECK_RUN")?;
    if nonce.is_empty() {
        return Err("empty SCOUT_CHECK_RUN");
    }
    if !nonce.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
    }) {
        return Err("SCOUT_CHECK_RUN contains unsafe characters");
    }
    Ok(nonce)
}

fn __scout_check_emit_error(reason: &str) {
    static ERROR_ONCE: std::sync::Once = std::sync::Once::new();
    ERROR_ONCE.call_once(|| {
        // Never echo an invalid value: whitespace/newlines would forge protocol fields.
        eprintln!("[SCOUT_CHECK_ERROR] INVALID {}", reason);
    });
}

macro_rules! scout_check_session {
    () => {{
        if $crate::__scout_check_observe_mode() {
            // Coverage-only replay runs before Crucible's stateful initializer.  Set
            // this per-thread flag here so failed actions terminate accumulated chains
            // exactly as they did in the stateful campaign that produced the corpus.
            $crate::__scout_crucible_test_context::set_stateful_chain_mode(true);
            static SESSION_ONCE: std::sync::Once = std::sync::Once::new();
            SESSION_ONCE.call_once(|| {
                match $crate::__scout_check_nonce() {
                    Ok(nonce) => eprintln!("[SCOUT_CHECK_SESSION] {}", nonce),
                    Err(reason) => $crate::__scout_check_emit_error(reason),
                }
            });
        }
    }};
}

// Gate the *entire* property computation, not only its final predicate.  This
// prevents another property's fallible reads, eligibility logic, or shadow-hook
// arithmetic from panicking/starving an isolated SCOUT_CHECK_ONLY replay.
macro_rules! scout_run_property {
    ($property:literal, $expression:expr $(,)?) => {{
        if $crate::__scout_check_selected($property) {
            let _ = $expression;
        }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __scout_check_impl {
    ($property:literal, $site:literal, $predicate:expr, $message:expr) => {{
        let __scout_observe = $crate::__scout_check_observe_mode();
        if !$crate::__scout_check_selected($property) {
            true
        } else {
            let __scout_nonce = if __scout_observe {
                Some($crate::__scout_check_nonce())
            } else {
                None
            };
            if let Some(Err(ref __scout_error)) = __scout_nonce {
                // An invalid session can never produce an EVALUATED marker.  The
                // mechanical verifier therefore cannot mistake it for sound evidence.
                $crate::__scout_check_emit_error(__scout_error);
                false
            } else {
                // Keep the predicate in one lexical/runtime position.  Expressions
                // with reads or counters are evaluated exactly once per selected check.
                let __scout_check_result: bool = $predicate;
                if let Some(Ok(ref __scout_run)) = __scout_nonce {
                    eprintln!(
                        "[SCOUT_CHECK_EVALUATED] {} {} {} {}:{}",
                        __scout_run, $property, $site, file!(), line!()
                    );
                    if !__scout_check_result {
                        eprintln!(
                            "[SCOUT_CHECK_WOULD_VIOLATE] {} {} {} {}:{}",
                            __scout_run, $property, $site, file!(), line!()
                        );
                    }
                } else if !__scout_check_result {
                    $crate::__scout_crucible_test_context::record_violation($message);
                }
                __scout_check_result
            }
        }
    }};
}

macro_rules! scout_check {
    ($property:literal, $site:literal, $predicate:expr $(,)?) => {{
        $crate::__scout_check_impl!(
            $property,
            $site,
            $predicate,
            format!(
                "Invariant {} check {} failed at {}:{}",
                $property, $site, file!(), line!()
            )
        )
    }};
    ($property:literal, $site:literal, $predicate:expr, $($arg:tt)+) => {{
        $crate::__scout_check_impl!($property, $site, $predicate, format!($($arg)+))
    }};
}
// SCOUT:CHECK-CONTRACT:END

const SCOUT_TARGET_PROGRAM_ARTIFACT: &str = "programs/onreapp.so";




// SCOUT:BINDINGS:BEGIN
// ---- program ids ----------------------------------------------------------------------------
// token_program = SPL_TOKEN_ID
// token_in_program = SPL_TOKEN_ID
// token_out_program = SPL_TOKEN_ID
// associated_token_program = ATA_PROGRAM_ID
// instructions_sysvar = INSTRUCTIONS_SYSVAR_ID
//
// ---- global PDAs ----------------------------------------------------------------------------
// state = self.state_pda
// mint_authority = self.mint_authority_pda
// vault_authority = self.offer_vault_authority
// offer_vault_authority = self.offer_vault_authority
// redemption_vault_authority = self.redemption_vault_authority
// permissionless_authority = self.permissionless_authority
// offer = self.offer_pda
// redemption_offer = self.redemption_offer_pda
//
// ---- the `initialize` triple ----------------------------------------------------------------
// Initialize.program = self.program_id
// Initialize.program_data = scout_pda(&[self.program_id.as_ref()], &BPF_LOADER_UPGRADEABLE_ID)
// Initialize.onyc_mint = self.mint_onyc
//
// ---- mints ----------------------------------------------------------------------------------
// The main offer is usdc -> onyc; the redemption offer is its inverse, so every redemption
// instruction has token_in/token_out the other way round.
// token_in_mint = self.mint_usdc
// token_out_mint = self.mint_onyc
// onyc_mint = self.mint_onyc
// CreateRedemptionRequest.token_in_mint = self.mint_onyc
// CancelRedemptionRequest.token_in_mint = self.mint_onyc
// FulfillRedemptionRequest.token_in_mint = self.mint_onyc
// FulfillRedemptionRequest.token_out_mint = self.mint_usdc
// MakeRedemptionOffer.token_in_mint = self.mint_onyc
// MakeRedemptionOffer.token_out_mint = self.mint_usdc
// UpdateRedemptionOfferFee.token_in_mint = self.mint_onyc
// UpdateRedemptionOfferFee.token_out_mint = self.mint_usdc
//
// `make_offer` is the one instruction whose offer must NOT already exist (`init`, not
// `init_if_needed`), so it gets the spare mint as its input leg and mints a genuinely new offer.
// The pair is chosen from `fee_basis_points`, so the fuzzer selects it. One of the four variants
// puts the same mint on both legs — legal as far as make_offer is concerned, and what P-0005 asserts
// must not be.
// MakeOffer.token_in_mint = self.make_offer_pair(fee_basis_points).0
// MakeOffer.token_out_mint = self.make_offer_pair(fee_basis_points).1
// MakeOffer.offer = self.make_offer_pda_for(fee_basis_points)
// MakeOffer.vault_token_in_account = scout_ata(&self.offer_vault_authority, &self.make_offer_pair(fee_basis_points).0, &SPL_TOKEN_ID)
//
// Likewise the mint-authority instructions operate on the spare mint, so they stay live instead
// of permanently failing against ONyc's already-transferred authority.
// TransferMintAuthorityToProgram.mint = self.mint_play
// TransferMintAuthorityToBoss.mint = self.mint_play
//
// ---- offer-side token accounts --------------------------------------------------------------
// vault_token_in_account = scout_ata(&self.offer_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID)
// vault_token_out_account = scout_ata(&self.offer_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID)
// boss_token_in_account = scout_ata(&self.boss.pubkey(), &self.mint_usdc, &SPL_TOKEN_ID)
// boss_onyc_account = scout_ata(&self.boss.pubkey(), &self.mint_onyc, &SPL_TOKEN_ID)
// permissionless_token_in_account = scout_ata(&self.permissionless_authority, &self.mint_usdc, &SPL_TOKEN_ID)
// permissionless_token_out_account = scout_ata(&self.permissionless_authority, &self.mint_onyc, &SPL_TOKEN_ID)
//
// `token_in_amount`'s low bit picks the acting user, so both actors really do trade against the
// same pools. A fixed single user makes every value-conservation property vacuous.
// TakeOffer.user = signer:self.pick_user(token_in_amount)
// TakeOffer.user_token_in_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_usdc, &SPL_TOKEN_ID)
// TakeOffer.user_token_out_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_onyc, &SPL_TOKEN_ID)
// TakeOfferPermissionless.user = signer:self.pick_user(token_in_amount)
// TakeOfferPermissionless.user_token_in_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_usdc, &SPL_TOKEN_ID)
// TakeOfferPermissionless.user_token_out_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_onyc, &SPL_TOKEN_ID)
// boss = self.boss.pubkey()
//
// ---- redemption-side token accounts ---------------------------------------------------------
// CreateRedemptionRequest.redeemer = signer:self.pick_user(amount)
// CreateRedemptionRequest.redeemer_token_account = scout_ata(&self.pick_user_pk(amount), &self.mint_onyc, &SPL_TOKEN_ID)
// CreateRedemptionRequest.vault_token_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID)
// CreateRedemptionRequest.redemption_request = self.next_request_pda()
//
// Fulfil/cancel act on the OLDEST live request, tracked harness-side, because the request PDA is
// seeded by a counter the harness cannot guess from the action's arguments.
// FulfillRedemptionRequest.redemption_request = self.oldest_request_pda()
// FulfillRedemptionRequest.redeemer = self.oldest_request_redeemer()
// FulfillRedemptionRequest.redemption_admin = signer:self.redemption_admin.insecure_clone()
// FulfillRedemptionRequest.offer = self.offer_pda
// FulfillRedemptionRequest.vault_token_in_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID)
// FulfillRedemptionRequest.vault_token_out_account = scout_ata(&self.redemption_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID)
// FulfillRedemptionRequest.user_token_out_account = scout_ata(&self.oldest_request_redeemer(), &self.mint_usdc, &SPL_TOKEN_ID)
// FulfillRedemptionRequest.boss_token_in_account = scout_ata(&self.boss.pubkey(), &self.mint_onyc, &SPL_TOKEN_ID)
//
// CancelRedemptionRequest.redemption_request = self.oldest_request_pda()
// CancelRedemptionRequest.redeemer = self.oldest_request_redeemer()
// CancelRedemptionRequest.redemption_admin = self.redemption_admin.pubkey()
// CancelRedemptionRequest.signer = signer:self.redemption_admin.insecure_clone()
// CancelRedemptionRequest.vault_token_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID)
// CancelRedemptionRequest.redeemer_token_account = scout_ata(&self.oldest_request_redeemer(), &self.mint_onyc, &SPL_TOKEN_ID)
//
// `make_redemption_offer` is `init`, so it cannot target the redemption offer setup already
// built. It is pointed at onyc -> play instead, whose underlying offer (seeds are the mints
// SWAPPED: [OFFER, token_out, token_in] = [OFFER, play, onyc]) is exactly what `action_make_offer`
// creates. That makes this a genuine two-action sequence the fuzzer has to discover, rather than
// an action that can never succeed.
// MakeRedemptionOffer.signer = signer:self.redemption_admin.insecure_clone()
// MakeRedemptionOffer.redemption_offer = scout_pda(&[SEED_REDEMPTION_OFFER, self.mint_onyc.as_ref(), self.mint_play.as_ref()], &self.program_id)
// MakeRedemptionOffer.offer = scout_pda(&[SEED_OFFER, self.mint_play.as_ref(), self.mint_onyc.as_ref()], &self.program_id)
// MakeRedemptionOffer.token_in_mint = self.mint_onyc
// MakeRedemptionOffer.token_out_mint = self.mint_play
// MakeRedemptionOffer.vault_token_in_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID)
// MakeRedemptionOffer.vault_token_out_account = scout_ata(&self.redemption_vault_authority, &self.mint_play, &SPL_TOKEN_ID)
//
// ---- market-info reads ----------------------------------------------------------------------
// onyc_vault_account = scout_ata(&self.offer_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID)
//
// ---- approval message ------------------------------------------------------------------------
// `None` for the plain actions: a valid ApprovalMessage is only accepted alongside an Ed25519
// precompile instruction in the SAME transaction, which a single-instruction `.send()` cannot
// carry. The approval-required path is driven by a compound action in SCOUT:EXTRA-ACTIONS.
// approval_message = None
// SetRedemptionAdmin.new_redemption_admin = self.redemption_admin.pubkey()
//
// ---- vault operations -----------------------------------------------------------------------
// OfferVaultDeposit.token_mint = self.mint_usdc
// OfferVaultDeposit.boss_token_account = scout_ata(&self.boss.pubkey(), &self.mint_usdc, &SPL_TOKEN_ID)
// OfferVaultDeposit.vault_token_account = scout_ata(&self.offer_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID)
// OfferVaultWithdraw.token_mint = self.mint_usdc
// OfferVaultWithdraw.boss_token_account = scout_ata(&self.boss.pubkey(), &self.mint_usdc, &SPL_TOKEN_ID)
// OfferVaultWithdraw.vault_token_account = scout_ata(&self.offer_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID)
// The redemption vault ops pick their mint from the fuzzer's `amount`, so they can reach the ONyc
// vault — the account that actually custodies user deposits from `create_redemption_request`.
// Pinning them to usdc would make P-0002's subject unreachable and the property permanently quiet.
// RedemptionVaultDeposit.token_mint = self.pick_vault_mint(amount)
// RedemptionVaultDeposit.boss_token_account = scout_ata(&self.boss.pubkey(), &self.pick_vault_mint(amount), &SPL_TOKEN_ID)
// RedemptionVaultDeposit.vault_token_account = scout_ata(&self.redemption_vault_authority, &self.pick_vault_mint(amount), &SPL_TOKEN_ID)
// RedemptionVaultWithdraw.token_mint = self.pick_vault_mint(amount)
// RedemptionVaultWithdraw.boss_token_account = scout_ata(&self.boss.pubkey(), &self.pick_vault_mint(amount), &SPL_TOKEN_ID)
// RedemptionVaultWithdraw.vault_token_account = scout_ata(&self.redemption_vault_authority, &self.pick_vault_mint(amount), &SPL_TOKEN_ID)
//
// ---- governance args ------------------------------------------------------------------------
// A fresh random pubkey per call would make `remove_admin`, `remove_approver` and `accept_boss`
// structurally unreachable — they can only ever match a key some earlier action installed. These
// bind to fixed, already-known keys so each add/remove pair actually closes.
//
// `propose_boss` nominates the CURRENT boss on purpose. Nominating anyone else lets `accept_boss`
// hand authority to a key the harness does not sign with, after which every `has_one = boss`
// instruction fails for the rest of the iteration — a self-inflicted coverage collapse, not a
// finding. Proposing the incumbent still exercises both instructions end to end.
// ProposeBoss.new_boss = self.boss.pubkey()
// AddAdmin.new_admin = self.user_a.pubkey()
// RemoveAdmin.admin_to_remove = self.user_a.pubkey()
// AddApprover.approver = self.approver.pubkey()
// RemoveApprover.approver = self.approver.pubkey()
// InitializePermissionlessAuthority.name = String::from("permissionless-1")
// AddOfferVector.start_time = None
// SCOUT:BINDINGS:END

// SCOUT:PRELUDE:BEGIN
// ---------------------------------------------------------------------------------------------
// Program IDs and PDA seeds.
//
// Seeds are copied from the target's `constants::seeds` (onre-sol/programs/onreapp/src/
// constants.rs). extract.py reports them as `unresolvable seed seeds::STATE` etc. because they are
// module constants, not literals, so every PDA in every action is bound from here.
// ---------------------------------------------------------------------------------------------
pub const SPL_TOKEN_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const SPL_TOKEN_2022_ID: Pubkey = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM_ID: Pubkey = Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const ED25519_PROGRAM_ID: Pubkey = Pubkey::from_str_const("Ed25519SigVerify111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey = Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111");
pub const BPF_LOADER_UPGRADEABLE_ID: Pubkey = Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");

pub const SEED_STATE: &[u8] = b"state";
pub const SEED_OFFER: &[u8] = b"offer";
pub const SEED_OFFER_VAULT_AUTHORITY: &[u8] = b"offer_vault_authority";
pub const SEED_PERMISSIONLESS_AUTHORITY: &[u8] = b"permissionless-1";
pub const SEED_MINT_AUTHORITY: &[u8] = b"mint_authority";
pub const SEED_REDEMPTION_OFFER: &[u8] = b"redemption_offer";
pub const SEED_REDEMPTION_OFFER_VAULT_AUTHORITY: &[u8] = b"redemption_offer_vault_authority";
pub const SEED_REDEMPTION_REQUEST: &[u8] = b"redemption_request";

/// Decimals chosen so the two legs differ — a same-decimals pair hides every scaling bug in
/// `calculate_token_out_amount` / `process_redemption_core`, which both convert across decimals.
pub const USDC_DECIMALS: u8 = 6;
pub const ONYC_DECIMALS: u8 = 9;

/// Starting balances. Large enough that a fuzzer-chosen u64 amount is usually affordable, small
/// enough that the u128 intermediates in the price math do not saturate on every call.
pub const USER_USDC_START: u64 = 1_000_000_000_000; // 1_000_000 USDC
pub const USER_ONYC_START: u64 = 100_000_000_000; // 100 ONyc
pub const VAULT_USDC_START: u64 = 1_000_000_000_000;

/// Upper bound on the redemption-request id space a property will walk. Beyond this the walk
/// returns None (check skipped) rather than a truncated sum -- a silently capped total would
/// under-report the claims against the vault and turn a real shortfall into a clean run.
pub const SCOUT_REQUEST_SCAN_CAP: u64 = 512;

/// Capacity of each property's registry of redemption requests it has seen created.
///
/// The predicate grammar admits only pure expressions plus a handful of trusted `ctx` reads, so a
/// property cannot derive a request PDA itself; it has to be handed the address at creation time.
/// If the ring wraps, the predicates bail out rather than sum a partial set — under-counting the
/// claims against the vault would turn a real shortfall into a clean run.
pub const SCOUT_REQ_CAP: usize = 32;

/// `RedemptionRequest`, borsh: 8 disc | offer 32 | request_id u64 8 | redeemer 32 | amount u64.
pub const SCOUT_REQ_AMOUNT_OFFSET: usize = 80;
pub const SCOUT_REQ_MIN_LEN: usize = 88;
/// `RedemptionRequest.offer` — the redemption offer a request is locked against.
///
/// Lets a solvency predicate scope its sum from ON-CHAIN data instead of trusting that whoever
/// appended to its registry appended only the right requests. With this check a mis-registration
/// can only UNDER-count (a miss), never inflate the claim and manufacture a shortfall against a
/// vault that never received the funds (a false positive).
pub const SCOUT_REQ_OFFER_OFFSET: usize = 8;
pub const SCOUT_REQ_OFFER_END: usize = 40;

/// Anchor's closed-account sentinel. `#[account(close = ...)]` zeroes an account's lamports and
/// overwrites its 8-byte discriminator with this marker; the DATA may still be readable until the
/// runtime purges it. A solvency/conservation predicate that treats "account_data returned Ok" as
/// "the request is open" would therefore sum a retired request against an aggregate that has
/// already dropped it — an OVER-count, the direction that manufactures violations.
pub const SCOUT_CLOSED_ACCOUNT_DISCRIMINATOR: [u8; 8] = [255, 255, 255, 255, 255, 255, 255, 255];

/// `spl_token::state::Account`: mint 32 | owner 32 | amount u64 at 64.
pub const SCOUT_TOKEN_AMOUNT_OFFSET: usize = 64;
pub const SCOUT_TOKEN_MIN_LEN: usize = 72;

/// `RedemptionOffer`, borsh: 8 disc | offer 32 | token_in 32 | token_out 32 | executed u128 16
/// -> requested_redemptions u128 at 120.
pub const SCOUT_RO_REQUESTED_OFFSET: usize = 120;
pub const SCOUT_RO_REQUESTED_MID: usize = 128;
pub const SCOUT_RO_MIN_LEN: usize = 136;

/// `State`, borsh: 8 disc | boss 32 | proposed_boss 32 | is_killed 1 | onyc_mint 32 (73..105)
/// | admins [Pubkey;20] 640 | approver1 32 | approver2 32 | bump 1 -> max_supply u64 at 810.
pub const SCOUT_STATE_ONYC_MINT_OFFSET: usize = 73;
pub const SCOUT_STATE_ONYC_MINT_END: usize = 105;
pub const SCOUT_STATE_MAX_SUPPLY_OFFSET: usize = 810;
pub const SCOUT_STATE_MAX_SUPPLY_END: usize = 818;

/// `spl_token::state::Mint`: mint_authority COption<Pubkey> 36 -> supply u64 at 36..44.
pub const SCOUT_MINT_SUPPLY_OFFSET: usize = 36;
pub const SCOUT_MINT_SUPPLY_END: usize = 44;

/// `Offer` (zero_copy, repr(C)): 8 disc | token_in_mint 32 (8..40) | token_out_mint 32 (40..72).
pub const SCOUT_OFFER_IN_MINT_OFFSET: usize = 8;
pub const SCOUT_OFFER_IN_MINT_END: usize = 40;
pub const SCOUT_OFFER_OUT_MINT_END: usize = 72;

/// Capacity of P-0005's registry of offer accounts.
pub const SCOUT_OFFER_CAP: usize = 16;

/// Capacity of P-0007's registry of ONyc-denominated redemption requests, pooled across EVERY
/// redemption offer whose token_in is ONyc — they all share one vault token account.
pub const SCOUT_P7_CAP: usize = 48;

/// `Offer` (zero_copy, repr(C), align 8): within-struct token_in_mint 0..32, token_out_mint 32..64,
/// vectors [OfferVector;10] 64..464 (5 x u64 each), fee_basis_points 464..466. Plus the 8-byte
/// account discriminator -> 472..474. Confirmed against the observed 608-byte account length.
pub const SCOUT_OFFER_FEE_OFFSET: usize = 472;
pub const SCOUT_OFFER_FEE_END: usize = 474;

/// `constants::MAX_ALLOWED_FEE_BPS` — the documented 10% ceiling on offer fees.
pub const SCOUT_MAX_ALLOWED_FEE_BPS: u16 = 1000;

pub fn scout_pda(seeds: &[&[u8]], program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program_id).0
}

/// Associated-token address. Every token account in this program is constrained with
/// `associated_token::{mint, authority, token_program}`, so a plain random pubkey is always
/// rejected — each one has to be minted at exactly this address.
pub fn scout_ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}

/// Mint a pre-funded SPL token account at its canonical ATA address.
pub fn scout_mk_ata(
    ctx: &mut TestContext,
    owner: &Pubkey,
    mint: &Pubkey,
    amount: u64,
) -> Pubkey {
    let addr = scout_ata(owner, mint, &SPL_TOKEN_ID);
    ctx.create_token_account()
        .pubkey(addr)
        .mint(*mint)
        .token_owner(*owner)
        .amount(amount)
        .create()
        .expect("setup: create ATA");
    addr
}

// ---------------------------------------------------------------------------------------------
// Token-2022 transfer-fee mints — a FIXTURE CAPABILITY, not a convenience.
//
// The program's OFFER path explicitly refuses a fee-bearing mint on either leg
// (`token_utils.rs:374,378`). The REDEMPTION path has no such guard: `has_transfer_fee` has
// exactly two call sites in the entire program and both are inside `execute_token_operations`,
// which only `take_offer` / `take_offer_permissionless` reach. `create_redemption_request` calls
// `transfer_tokens` directly.
//
// Without a fee-bearing mint in the world, amplifier #8 (amount != accounting) is structurally
// UNOBSERVABLE on the redemption path — a clean campaign would mean "the fixture cannot express
// it", not "the program is safe". That distinction is the whole reason these exist.
// ---------------------------------------------------------------------------------------------

/// Transfer fee on `mint_fee`, in basis points. 1% is large enough that the shortfall is obvious
/// in a log line and small enough to stay far from the `maximum_fee` clamp.
pub const SCOUT_T22_FEE_BPS: u16 = 100;
pub const FEE_DECIMALS: u8 = 6;

/// Build a Token-2022 mint carrying a live `TransferFeeConfig`, owned by the Token-2022 program.
///
/// Both epoch slots carry the same fee, so the effective rate does not depend on which epoch the
/// SVM happens to be in — `has_transfer_fee` reads `get_epoch_fee(clock.epoch)`, and a fixture
/// whose fee silently switched off at an epoch boundary would produce an unreproducible campaign.
pub fn scout_mk_t22_fee_mint(
    ctx: &mut TestContext,
    authority: &Pubkey,
    decimals: u8,
    supply: u64,
    fee_bps: u16,
) -> Pubkey {
    use spl_token_2022_interface::extension::{
        transfer_fee::TransferFeeConfig, BaseStateWithExtensionsMut, ExtensionType,
        StateWithExtensionsMut,
    };
    use solana_program_option::COption;
    use spl_token_2022_interface::state::Mint as T22Mint;

    let addr = Keypair::new().pubkey();
    let len =
        ExtensionType::try_calculate_account_len::<T22Mint>(&[ExtensionType::TransferFeeConfig])
            .expect("setup: t22 mint account len");
    let mut data = vec![0u8; len];
    {
        let mut st = StateWithExtensionsMut::<T22Mint>::unpack_uninitialized(&mut data)
            .expect("setup: t22 unpack_uninitialized");
        let cfg = st
            .init_extension::<TransferFeeConfig>(true)
            .expect("setup: init TransferFeeConfig");
        for fee in [&mut cfg.older_transfer_fee, &mut cfg.newer_transfer_fee] {
            fee.epoch = 0u64.into();
            fee.maximum_fee = u64::MAX.into();
            fee.transfer_fee_basis_points = fee_bps.into();
        }
        st.base = T22Mint {
            mint_authority: COption::Some(*authority),
            supply,
            decimals,
            is_initialized: true,
            freeze_authority: COption::None,
        };
        st.pack_base();
        st.init_account_type().expect("setup: t22 init_account_type");
    }
    ctx.create_account()
        .pubkey(addr)
        .owner(SPL_TOKEN_2022_ID)
        .data(&data)
        .create()
        .expect("setup: create t22 fee mint");
    addr
}

/// Mint a pre-funded **Token-2022** account at its canonical ATA address.
///
/// A token account for a mint carrying `TransferFeeConfig` must itself carry `TransferFeeAmount`,
/// or the Token-2022 program rejects every transfer touching it. Building this by hand rather
/// than through `create_token_account()` is what that requirement forces.
pub fn scout_mk_t22_ata(
    ctx: &mut TestContext,
    owner: &Pubkey,
    mint: &Pubkey,
    amount: u64,
) -> Pubkey {
    use spl_token_2022_interface::extension::{
        transfer_fee::TransferFeeAmount, BaseStateWithExtensionsMut, ExtensionType,
        StateWithExtensionsMut,
    };
    use solana_program_option::COption;
    use spl_token_2022_interface::state::{Account as T22Account, AccountState as T22AccountState};

    let addr = scout_ata(owner, mint, &SPL_TOKEN_2022_ID);
    let len =
        ExtensionType::try_calculate_account_len::<T22Account>(&[ExtensionType::TransferFeeAmount])
            .expect("setup: t22 token account len");
    let mut data = vec![0u8; len];
    {
        let mut st = StateWithExtensionsMut::<T22Account>::unpack_uninitialized(&mut data)
            .expect("setup: t22 account unpack_uninitialized");
        st.init_extension::<TransferFeeAmount>(true)
            .expect("setup: init TransferFeeAmount");
        st.base = T22Account {
            mint: *mint,
            owner: *owner,
            amount,
            delegate: COption::None,
            state: T22AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        };
        st.pack_base();
        st.init_account_type().expect("setup: t22 account type");
    }
    ctx.create_account()
        .pubkey(addr)
        .owner(SPL_TOKEN_2022_ID)
        .data(&data)
        .create()
        .expect("setup: create t22 ATA");
    addr
}

/// setup() must abort loudly on a failed prerequisite: a silently-skipped step leaves a world that
/// looks built but is not, and every downstream action then fails for a reason that has nothing to
/// do with the action.
pub fn scout_expect_ok(label: &str, out: anyhow::Result<TxOutcome>) {
    match out {
        Ok(o) if o.is_success() => {}
        Ok(o) => panic!(
            "setup step `{}` failed (code {:?})\nlogs:\n{}",
            label,
            o.error_code(),
            o.logs().join("\n")
        ),
        Err(e) => panic!("setup step `{}` errored: {e:?}", label),
    }
}

// ---------------------------------------------------------------------------------------------
// Clock control.
//
// Every price this program quotes is a function of `Clock::get()` — `calculate_step_price_at`
// snaps to the end of the current `price_fix_duration` window, and `find_active_vector_at` picks a
// vector by `start_time <= now`. A harness that never moves the clock quotes ONE price forever and
// silently deletes the entire class of bugs that only appears when the price moves between two
// user actions. So: pin the clock to a known epoch in setup, and expose advancing it as an action.
// ---------------------------------------------------------------------------------------------
pub const SCOUT_GENESIS_TS: i64 = 1_700_000_000;

pub fn scout_now(ctx: &TestContext) -> u64 {
    ctx.svm.get_sysvar::<crucible_fuzzer::anchor_lang::prelude::Clock>().unix_timestamp as u64
}

pub fn scout_set_time(ctx: &mut TestContext, unix_timestamp: i64) {
    let mut clock = ctx.svm.get_sysvar::<crucible_fuzzer::anchor_lang::prelude::Clock>();
    clock.unix_timestamp = unix_timestamp;
    ctx.set_sysvar(&clock);
}

/// Create the `State` account and wire up governance.
///
/// Shared by `setup()` and the `close_state` action hook: `close_state` deliberately deallocates
/// the state PDA, which would otherwise brick every remaining action in the iteration and read as
/// a coverage collapse rather than as the destructive-by-design instruction it is. Re-running this
/// afterwards restores the world WITHOUT weakening the action — close_state still really executes
/// and still really covers its own lines.
pub fn scout_bootstrap_state(
    ctx: &mut TestContext,
    program_id: Pubkey,
    boss: &Keypair,
    redemption_admin: &Pubkey,
    approver: &Pubkey,
    mint_onyc: Pubkey,
    state_pda: Pubkey,
    mint_authority_pda: Pubkey,
    offer_vault_authority: Pubkey,
) {
    let program_data = scout_pda(&[program_id.as_ref()], &BPF_LOADER_UPGRADEABLE_ID);
    scout_expect_ok(
        "initialize",
        ctx.program(program_id)
            .call(instruction::Initialize {})
            .accounts(accounts::Initialize {
                state: state_pda,
                mint_authority: mint_authority_pda,
                offer_vault_authority,
                boss: boss.pubkey(),
                program_data: Some(program_data),
                onyc_mint: mint_onyc,
            })
            .signers(&[boss])
            .send(),
    );
    scout_expect_ok(
        "set_redemption_admin",
        ctx.program(program_id)
            .call(instruction::SetRedemptionAdmin {
                new_redemption_admin: *redemption_admin,
            })
            .accounts(accounts::SetRedemptionAdmin {
                state: state_pda,
                boss: boss.pubkey(),
            })
            .signers(&[boss])
            .send(),
    );
    scout_expect_ok(
        "add_approver",
        ctx.program(program_id)
            .call(instruction::AddApprover {
                approver: *approver,
            })
            .accounts(accounts::AddApprover {
                state: state_pda,
                boss: boss.pubkey(),
            })
            .signers(&[boss])
            .send(),
    );
}

// ---------------------------------------------------------------------------------------------
// Ed25519 precompile instruction.
//
// Hand-built rather than pulled from a Solana crate because the target parses the layout itself
// (`utils/ed25519_parser.rs`) and additionally REQUIRES all three instruction indices to be
// u16::MAX — i.e. every field must live in this instruction's own data. The account list must be
// empty; `verify_approval_message_generic` rejects the instruction outright otherwise.
//
// Layout (16-byte header, then the fixed-position payload):
//   0      num_signatures = 1
//   1      padding
//   2..4   signature_offset            4..6   signature_instruction_index   = u16::MAX
//   6..8   public_key_offset           8..10  public_key_instruction_index  = u16::MAX
//   10..12 message_data_offset        12..14  message_data_size
//   14..16 message_instruction_index  = u16::MAX
// ---------------------------------------------------------------------------------------------
pub fn scout_ed25519_instruction(
    pubkey: &Pubkey,
    signature: &[u8; 64],
    message: &[u8],
) -> solana_instruction::Instruction {
    const HEADER: usize = 16;
    let pubkey_offset = HEADER;
    let signature_offset = pubkey_offset + 32;
    let message_offset = signature_offset + 64;

    let mut data = Vec::with_capacity(message_offset + message.len());
    data.push(1u8); // num_signatures
    data.push(0u8); // padding
    data.extend_from_slice(&(signature_offset as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&(pubkey_offset as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&(message_offset as u16).to_le_bytes());
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(pubkey.as_ref());
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    solana_instruction::Instruction {
        program_id: ED25519_PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

// ---------------------------------------------------------------------------------------------
// Fixture helpers.
//
// These live in SCOUT:PRELUDE rather than beside the generated actions because everything outside
// a SCOUT region is deleted verbatim on the next `scout regen`. A second `impl` block at file
// scope is regeneration-safe and `#[fuzz_fixture]` only inspects the block it is attached to, so
// nothing here is mistaken for an action.
// ---------------------------------------------------------------------------------------------
impl OnreappFixture {
    /// Pick one of the two non-privileged actors from a fuzzer-chosen value.
    ///
    /// Derived from the action's own amount argument so the FUZZER controls who acts. Hard-wiring
    /// a single user would make every adversary-value property vacuous: with one actor, every
    /// transfer is self-to-self and no one can end richer at anyone else's expense.
    pub fn pick_user(&self, sel: u64) -> Keypair {
        if sel & 1 == 0 {
            self.user_a.insecure_clone()
        } else {
            self.user_b.insecure_clone()
        }
    }

    pub fn pick_user_pk(&self, sel: u64) -> Pubkey {
        if sel & 1 == 0 {
            self.user_a.pubkey()
        } else {
            self.user_b.pubkey()
        }
    }

    /// Address of request `id` under an arbitrary redemption offer.
    pub fn request_pda_of(&self, ro: &Pubkey, id: u64) -> Pubkey {
        scout_pda(
            &[SEED_REDEMPTION_REQUEST, ro.as_ref(), &id.to_le_bytes()],
            &self.program_id,
        )
    }

    /// `request_counter` of an arbitrary redemption offer.
    pub fn request_counter_of(&self, ro: &Pubkey) -> Option<u64> {
        let data = self.ctx.account_data(ro).ok()?;
        if data.len() < 146 { return None; }
        Some(u64::from_le_bytes(data[138..146].try_into().ok()?))
    }

    /// Open requests under an arbitrary redemption offer, as `(id, redeemer, amount)`.
    pub fn open_requests_of(&self, ro: &Pubkey) -> Option<Vec<(u64, Pubkey, u64)>> {
        let counter = self.request_counter_of(ro)?;
        if counter > SCOUT_REQUEST_SCAN_CAP { return None; }
        let mut out = Vec::new();
        for id in 0..counter {
            let pda = self.request_pda_of(ro, id);
            let data = match self.ctx.account_data(&pda) {
                Ok(d) if d.len() >= SCOUT_REQ_MIN_LEN => d,
                _ => continue,
            };
            let redeemer = Pubkey::new_from_array(data[48..80].try_into().ok()?);
            let amount = u64::from_le_bytes(
                data[SCOUT_REQ_AMOUNT_OFFSET..SCOUT_REQ_MIN_LEN].try_into().ok()?,
            );
            out.push((id, redeemer, amount));
        }
        Some(out)
    }

    /// Current ONyc supply, read straight out of the mint account (offset 36 of spl Mint).
    pub fn onyc_supply(&self) -> Option<u64> {
        let data = self.ctx.account_data(&self.mint_onyc).ok()?;
        if data.len() < 44 { return None; }
        Some(u64::from_le_bytes(data[36..44].try_into().ok()?))
    }

    /// Address of the redemption request with a given id under the live redemption offer.
    pub fn request_pda(&self, id: u64) -> Pubkey {
        scout_pda(
            &[
                SEED_REDEMPTION_REQUEST,
                self.redemption_offer_pda.as_ref(),
                &id.to_le_bytes(),
            ],
            &self.program_id,
        )
    }

    /// `RedemptionOffer.request_counter` — the seed the NEXT request will be derived from.
    ///
    /// Read from the chain rather than mirrored harness-side. A mirror would be a second source of
    /// truth that can silently drift from the program, and every property below would then be
    /// measuring the drift rather than the protocol.
    pub fn onchain_request_counter(&self) -> Option<u64> {
        let data = self.ctx.account_data(&self.redemption_offer_pda).ok()?;
        // borsh, no padding: 8 disc | offer 32 | token_in 32 | token_out 32 | executed u128 16
        //   -> requested u128 16 (120..136) | fee_basis_points u16 (136..138) | counter u64 138..146
        if data.len() < 146 { return None; }
        Some(u64::from_le_bytes(data[138..146].try_into().ok()?))
    }

    /// `RedemptionOffer.requested_redemptions` as the program currently records it.
    pub fn onchain_requested_redemptions(&self) -> Option<u128> {
        let data = self.ctx.account_data(&self.redemption_offer_pda).ok()?;
        if data.len() < 136 { return None; }
        Some(u128::from_le_bytes(data[120..136].try_into().ok()?))
    }

    /// Every redemption request account that still exists, as `(id, redeemer, amount)`.
    ///
    /// Ground truth, walked from the chain: fulfil and cancel both `close` the account, so
    /// "the account is still there" IS "the request is still open" — there is no status field to
    /// misread and no shadow ledger to desynchronise.
    ///
    /// Returns `None` rather than a partial answer if the counter has run past `SCOUT_REQUEST_SCAN_CAP`;
    /// a silently truncated sum would under-report and turn a real shortfall into a clean run.
    pub fn open_requests(&self) -> Option<Vec<(u64, Pubkey, u64)>> {
        let counter = self.onchain_request_counter()?;
        if counter > SCOUT_REQUEST_SCAN_CAP { return None; }
        let mut out = Vec::new();
        for id in 0..counter {
            let pda = self.request_pda(id);
            let data = match self.ctx.account_data(&pda) {
                Ok(d) if d.len() >= 88 => d,
                _ => continue, // closed by fulfil/cancel, or never created
            };
            // 8 disc | offer 32 | request_id u64 8 | redeemer 32 (48..80) | amount u64 80..88
            let redeemer = Pubkey::new_from_array(data[48..80].try_into().ok()?);
            let amount = u64::from_le_bytes(data[80..88].try_into().ok()?);
            out.push((id, redeemer, amount));
        }
        Some(out)
    }

    /// Total token_in still locked on behalf of open requests, denominated in the live redemption
    /// offer's token_in (ONyc — the bindings pin `create_redemption_request` to that offer).
    pub fn open_request_total(&self) -> Option<u128> {
        Some(self.open_requests()?.iter().map(|(_, _, a)| *a as u128).sum())
    }

    /// PDA the next `create_redemption_request` will open.
    pub fn next_request_pda(&self) -> Pubkey {
        self.request_pda(self.onchain_request_counter().unwrap_or(0))
    }

    /// The oldest still-open request — what fulfil and cancel are bound to operate on.
    ///
    /// With no open request this returns the NEXT request's address, which does not exist yet, so
    /// the action fails. That is the honest outcome: there is nothing to fulfil or cancel.
    pub fn oldest_request_pda(&self) -> Pubkey {
        match self.open_requests().as_ref().and_then(|v| v.first()) {
            Some((id, _, _)) => self.request_pda(*id),
            None => self.next_request_pda(),
        }
    }

    pub fn oldest_request_redeemer(&self) -> Pubkey {
        match self.open_requests().as_ref().and_then(|v| v.first()) {
            Some((_, redeemer, _)) => *redeemer,
            None => self.user_a.pubkey(),
        }
    }

    /// Whether the program's `State` account is currently allocated. `close_state` deallocates it.
    pub fn state_exists(&self) -> bool {
        self.ctx.account_data(&self.state_pda).map(|d| d.len() >= 40).unwrap_or(false)
    }

    /// The (token_in, token_out) pair the generated `make_offer` action uses, chosen from its own
    /// fee argument so the FUZZER decides.
    ///
    /// Variant 3 puts the SAME mint on both legs. That is not a harness contrivance: `make_offer`
    /// relates the two mint arguments nowhere, so this is an ordinary accepted call — and it is the
    /// only way the fuzzer can reach the state P-0005 forbids through a real IDL instruction rather
    /// than a bespoke harness action.
    pub fn make_offer_pair(&self, sel: u16) -> (Pubkey, Pubkey) {
        match sel % 4 {
            0 => (self.mint_play, self.mint_onyc),
            1 => (self.mint_play, self.mint_usdc),
            2 => (self.mint_appr, self.mint_usdc),
            _ => (self.mint_onyc, self.mint_onyc),
        }
    }

    pub fn make_offer_pda_for(&self, sel: u16) -> Pubkey {
        let (a, b) = self.make_offer_pair(sel);
        scout_pda(&[SEED_OFFER, a.as_ref(), b.as_ref()], &self.program_id)
    }

    /// Which vault mint a vault-operation action targets, chosen from a fuzzer value.

    ///
    /// Pinning these to one mint would leave the ONyc redemption vault — the account that actually
    /// custodies user deposits from `create_redemption_request` — untouchable by
    /// `redemption_vault_withdraw`/`_deposit`, and P-0002's whole subject would be unreachable.
    pub fn pick_vault_mint(&self, sel: u64) -> Pubkey {
        if sel & 1 == 0 { self.mint_usdc } else { self.mint_onyc }
    }

    /// The single ATA that custodies every redemption deposit for a mint.
    ///
    /// `seeds::REDEMPTION_OFFER_VAULT_AUTHORITY` carries no per-offer discriminator, so this one
    /// account backs every redemption offer sharing the mint.
    pub fn redemption_vault_ata(&self, mint: &Pubkey) -> Pubkey {
        scout_ata(&self.redemption_vault_authority, mint, &SPL_TOKEN_ID)
    }

    /// Rebuild `State` after `close_state` deallocated it. See `scout_bootstrap_state`.
    pub fn rebuild_state(&mut self) {
        let boss = self.boss.insecure_clone();
        let redemption_admin = self.redemption_admin.pubkey();
        let approver = self.approver.pubkey();
        scout_bootstrap_state(
            &mut self.ctx,
            self.program_id,
            &boss,
            &redemption_admin,
            &approver,
            self.mint_onyc,
            self.state_pda,
            self.mint_authority_pda,
            self.offer_vault_authority,
        );
    }
}
// SCOUT:PRELUDE:END

crucible_idl_gen::declare_fuzz_program!("idls/onreapp.json");

use onreapp::{accounts, instruction};

#[derive(Clone)]
struct OnreappFixture {
    ctx: crate::__scout_crucible_test_context::TestContext,
    program_id: Pubkey,
    payer: Rc<Keypair>,
    // SCOUT:FIELDS:BEGIN
    // --- actors -------------------------------------------------------------------------------
    /// Program authority. Identical to `payer`, so the generator's `boss = self.payer.pubkey()`
    /// default is already correct for every `has_one = boss` instruction.
    boss: Rc<Keypair>,
    /// Two non-privileged actors. Distinct signers are what make an adversary-value-conservation
    /// property meaningful — with one user every transfer is self-to-self and nothing can be stolen.
    user_a: Rc<Keypair>,
    user_b: Rc<Keypair>,
    /// `state.redemption_admin`; the only signer `fulfill_redemption_request` accepts.
    redemption_admin: Rc<Keypair>,
    /// `state.approver1`; signs `ApprovalMessage`s for offers with `needs_approval`.
    approver: Rc<Keypair>,

    // --- mints --------------------------------------------------------------------------------
    /// 6 decimals, mint authority stays with `boss` — the program never controls it, so it always
    /// takes the transfer (not burn/mint) path in `execute_token_operations`.
    mint_usdc: Pubkey,
    /// 9 decimals, mint authority moved to the `mint_authority` PDA during setup — the program
    /// controls it, so it takes the burn/mint path. This is `state.onyc_mint`.
    mint_onyc: Pubkey,
    /// 6 decimals, authority left with `boss` and used by nothing in the built world. Exists so
    /// `transfer_mint_authority_to_{program,boss}` and `make_offer` have a live target at fuzz
    /// time instead of being permanently dead against already-configured mints.
    mint_play: Pubkey,

    // --- PDAs ---------------------------------------------------------------------------------
    state_pda: Pubkey,
    mint_authority_pda: Pubkey,
    offer_vault_authority: Pubkey,
    redemption_vault_authority: Pubkey,
    permissionless_authority: Pubkey,
    /// The main offer: usdc -> onyc.
    offer_pda: Pubkey,
    /// The inverse redemption offer: onyc -> usdc.
    redemption_offer_pda: Pubkey,
    /// The REVERSE offer, onyc -> usdc. Exists solely so a redemption offer can be created whose
    /// payout leg is the program-controlled ONyc mint — the only shape in which
    /// `fulfill_redemption_request` reaches `mint_tokens`, and therefore the only shape in which
    /// its hard-coded `token_out_max_supply: 0` is observable.
    offer_rev_pda: Pubkey,
    /// Redemption offer usdc -> onyc, the inverse of `offer_rev_pda`. Fulfilling one of its
    /// requests MINTS ONyc.
    redemption_offer_rev_pda: Pubkey,

    /// The single token account that custodies every ONyc redemption deposit. Precomputed because
    /// a predicate cannot derive an address itself.
    redemption_vault_onyc: Pubkey,

    // --- per-property request registries ------------------------------------------------------
    // Each property keeps its OWN registry rather than sharing one: an isolated single-property
    // replay runs exactly one of the hooks below, so a shared counter would advance a different
    // number of times depending on which property was selected.
    //
    // These record only that a request was CREATED. Whether it is still open is decided in the
    // predicate by reading the account — fulfil and cancel both `close` it, so "the account is
    // still there" IS "the request is still open". No liveness is mirrored, so none can drift.
    /// Every ONyc-denominated redemption request the harness has watched be created, pooled
    /// across offers. `seeds::REDEMPTION_OFFER_VAULT_AUTHORITY` has no per-offer discriminator, so
    /// one token account backs them all — P-0007 asks whether that pooled account stays solvent.
    scout_p7_reqs: [Pubkey; SCOUT_P7_CAP],
    scout_p7_next: usize,

    /// Offer registry, retired with P-0005's and then P-0006's blocks (kept so restoring either
    /// is a one-block edit).
    #[allow(dead_code)]
    scout_p5_offers: [Pubkey; SCOUT_OFFER_CAP],
    #[allow(dead_code)]
    scout_p5_next: usize,

    /// Retired with P-0002's block (kept so restoring it is a one-block edit).
    #[allow(dead_code)]
    scout_p2_reqs: [Pubkey; SCOUT_REQ_CAP],
    #[allow(dead_code)]
    scout_p2_next: usize,
    scout_p3_reqs: [Pubkey; SCOUT_REQ_CAP],
    scout_p3_next: usize,
    /// 6 decimals, authority stays with `boss`. Input leg of the approval-gated offer.
    mint_appr: Pubkey,
    /// An offer with `needs_approval = true`: mint_appr -> onyc. Only reachable through the
    /// compound action that prepends a real Ed25519 instruction.
    offer_appr_pda: Pubkey,

    /// A **Token-2022 mint carrying a live `TransferFeeConfig`** (`SCOUT_T22_FEE_BPS`).
    ///
    /// The program advertises Token-2022 support and refuses fee-bearing mints on the OFFER path
    /// only (`token_utils.rs:374,378`). Without this mint the redemption path's complete absence
    /// of that guard is unobservable — every campaign would come back clean because the world
    /// contains nothing whose transferred amount differs from its requested amount.
    mint_fee: Pubkey,
    /// `make_offer(usdc -> fee)`. Exists solely so the redemption offer below has the `offer`
    /// account its seeds require (`[OFFER, token_out_mint, token_in_mint]`, mints swapped).
    offer_fee_pda: Pubkey,
    /// `make_redemption_offer(fee -> usdc)` — the redemption offer whose token_in charges a
    /// transfer fee. `create_redemption_request` against it is fully permissionless.
    redemption_offer_fee_pda: Pubkey,
    /// The pooled redemption vault ATA for `mint_fee`. Stored rather than derived because the
    /// invariant predicate grammar admits no helper calls — `scout_ata` cannot be called there.
    redemption_vault_fee_ata: Pubkey,
    /// P-0008's registry of requests opened against the transfer-fee redemption offer.
    scout_p8_reqs: [Pubkey; SCOUT_REQ_CAP],
    scout_p8_next: usize,
    // SCOUT:FIELDS:END
}

#[fuzz_fixture]
impl OnreappFixture {
    fn scout_placeholder(&self) -> Pubkey { Pubkey::new_unique() }

    pub fn setup() -> Self {
        let mut ctx = crate::__scout_crucible_test_context::TestContext::new();
        let program_id = Pubkey::new_from_array(onreapp::ID.to_bytes());
        // SCOUT:TARGET-PROGRAM:BEGIN
        crate::__scout_crucible_test_context::TestContext::add_program(&mut ctx, &program_id, SCOUT_TARGET_PROGRAM_ARTIFACT).unwrap();
        // SCOUT:TARGET-PROGRAM:END
        let payer = Rc::new(Keypair::new());
        ctx.create_account().pubkey(payer.pubkey()).lamports(1_000_000_000)
            .owner(system_program::ID).create().unwrap();
        // SCOUT:SETUP-GLUE:BEGIN
        // -----------------------------------------------------------------------------------
        // 1. Actors.
        //
        // The generated `payer` above got 1 SOL, which does not survive the number of
        // `init_if_needed` ATAs this program opens (take_offer, mint_to, fulfill and cancel each
        // may create one). Re-create it with a balance that does.
        // -----------------------------------------------------------------------------------
        let boss = payer.clone();
        ctx.create_account()
            .pubkey(boss.pubkey())
            .lamports(1_000_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        let user_a = Rc::new(Keypair::new());
        let user_b = Rc::new(Keypair::new());
        let redemption_admin = Rc::new(Keypair::new());
        let approver = Rc::new(Keypair::new());
        for actor in [&user_a, &user_b, &redemption_admin, &approver] {
            ctx.create_account()
                .pubkey(actor.pubkey())
                .lamports(1_000_000_000_000)
                .owner(system_program::ID)
                .create()
                .unwrap();
        }

        // -----------------------------------------------------------------------------------
        // 2. PDAs.
        // -----------------------------------------------------------------------------------
        let state_pda = scout_pda(&[SEED_STATE], &program_id);
        let mint_authority_pda = scout_pda(&[SEED_MINT_AUTHORITY], &program_id);
        let offer_vault_authority = scout_pda(&[SEED_OFFER_VAULT_AUTHORITY], &program_id);
        let redemption_vault_authority =
            scout_pda(&[SEED_REDEMPTION_OFFER_VAULT_AUTHORITY], &program_id);
        let permissionless_authority =
            scout_pda(&[SEED_PERMISSIONLESS_AUTHORITY], &program_id);

        // -----------------------------------------------------------------------------------
        // 3. Mints.
        //
        // `supply` is seeded to exactly the sum of the balances handed out below. The token
        // program only updates supply on mint/burn, so leaving it at 0 while pre-funding accounts
        // would make `get_circulating_supply` / `get_tvl` / the max-supply cap read a supply that
        // is smaller than the tokens that actually exist — a harness artefact that would show up
        // as a conservation violation with no bug behind it.
        // -----------------------------------------------------------------------------------
        let usdc_supply = USER_USDC_START * 2 + VAULT_USDC_START;
        let onyc_supply = USER_ONYC_START * 2;

        let mint_usdc = ctx
            .create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(USDC_DECIMALS)
            .mint_authority(boss.pubkey())
            .supply(usdc_supply)
            .create()
            .unwrap();
        let mint_onyc = ctx
            .create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(ONYC_DECIMALS)
            .mint_authority(boss.pubkey())
            .supply(onyc_supply)
            .create()
            .unwrap();
        let mint_play = ctx
            .create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(USDC_DECIMALS)
            .mint_authority(boss.pubkey())
            .supply(0)
            .create()
            .unwrap();

        // -----------------------------------------------------------------------------------
        // 4. Pin the clock, then initialize + wire governance.
        //
        // litesvm's `add_program` deploys under BPFLoaderUpgradeable and writes a real ProgramData
        // account with `upgrade_authority_address: None`, which is exactly what
        // `get_upgrade_authority` needs to return `Ok(None)` and let any signer become boss.
        // -----------------------------------------------------------------------------------
        scout_set_time(&mut ctx, SCOUT_GENESIS_TS);
        scout_bootstrap_state(
            &mut ctx,
            program_id,
            &boss,
            &redemption_admin.pubkey(),
            &approver.pubkey(),
            mint_onyc,
            state_pda,
            mint_authority_pda,
            offer_vault_authority,
        );

        // -----------------------------------------------------------------------------------
        // 6. Hand ONyc's mint authority to the program.
        //
        // Done through the real instruction rather than by writing the mint directly, so the
        // `program_controls_mint` == true side of every burn/mint branch is reachable AND this
        // instruction's own happy path is covered.
        // -----------------------------------------------------------------------------------
        scout_expect_ok(
            "transfer_mint_authority_to_program(onyc)",
            ctx.program(program_id)
                .call(instruction::TransferMintAuthorityToProgram {})
                .accounts(accounts::TransferMintAuthorityToProgram {
                    boss: boss.pubkey(),
                    state: state_pda,
                    mint: mint_onyc,
                    mint_authority: mint_authority_pda,
                    token_program: SPL_TOKEN_ID,
                })
                .signers(&[&boss])
                .send(),
        );

        // -----------------------------------------------------------------------------------
        // 7. Token accounts.
        //
        // Pre-minting these is safe against the `init_if_needed` ATAs in make_offer /
        // make_redemption_offer / take_offer: `init_if_needed` accepts an already-correct ATA, so
        // none of those actions is disabled by minting here (contrast with an `init`-only target,
        // which pre-minting WOULD kill permanently).
        // -----------------------------------------------------------------------------------
        for (owner, mint, amount) in [
            (boss.pubkey(), mint_usdc, 0u64),
            (boss.pubkey(), mint_onyc, 0),
            (boss.pubkey(), mint_play, 0),
            (user_a.pubkey(), mint_usdc, USER_USDC_START),
            (user_a.pubkey(), mint_onyc, USER_ONYC_START),
            (user_b.pubkey(), mint_usdc, USER_USDC_START),
            (user_b.pubkey(), mint_onyc, USER_ONYC_START),
            (offer_vault_authority, mint_usdc, 0),
            (offer_vault_authority, mint_onyc, 0),
            (redemption_vault_authority, mint_usdc, VAULT_USDC_START),
            (redemption_vault_authority, mint_onyc, 0),
            (permissionless_authority, mint_usdc, 0),
            (permissionless_authority, mint_onyc, 0),
        ] {
            scout_mk_ata(&mut ctx, &owner, &mint, amount);
        }

        // -----------------------------------------------------------------------------------
        // 8. The main offer: usdc -> onyc, no approval required, permissionless allowed.
        //
        // `needs_approval = false` so the plain generated `action_take_offer` can succeed at all;
        // the approval-required branch needs an ed25519 instruction in the same transaction and is
        // driven by a compound action instead.
        // -----------------------------------------------------------------------------------
        let offer_pda = scout_pda(
            &[SEED_OFFER, mint_usdc.as_ref(), mint_onyc.as_ref()],
            &program_id,
        );
        scout_expect_ok(
            "make_offer(usdc->onyc)",
            ctx.program(program_id)
                .call(instruction::MakeOffer {
                    fee_basis_points: 100,
                    needs_approval: false,
                    allow_permissionless: true,
                })
                .accounts(accounts::MakeOffer {
                    vault_authority: offer_vault_authority,
                    token_in_mint: mint_usdc,
                    token_in_program: SPL_TOKEN_ID,
                    vault_token_in_account: scout_ata(
                        &offer_vault_authority,
                        &mint_usdc,
                        &SPL_TOKEN_ID,
                    ),
                    token_out_mint: mint_onyc,
                    offer: offer_pda,
                    state: state_pda,
                    boss: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );

        // A pricing vector, without which every take/redeem path dies at `NoActiveVector` and the
        // whole value-flow surface reads as unreachable.
        //   start_time = None -> max(now, base_time); base_time = now => active immediately.
        let now = scout_now(&ctx);
        scout_expect_ok(
            "add_offer_vector(usdc->onyc)",
            ctx.program(program_id)
                .call(instruction::AddOfferVector {
                    start_time: None,
                    base_time: now,
                    base_price: 1_000_000_000, // 1.0 with PRICE_DECIMALS = 9
                    apr: 5_000_000,            // 5% (scale 1e6 == 1%)
                    price_fix_duration: 3_600,
                })
                .accounts(accounts::AddOfferVector {
                    offer: offer_pda,
                    token_in_mint: mint_usdc,
                    token_out_mint: mint_onyc,
                    state: state_pda,
                    boss: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );

        // -----------------------------------------------------------------------------------
        // 8b. An approval-gated offer: mint_appr -> onyc, `needs_approval = true`.
        //
        // Separate from the main offer because `needs_approval` is fixed at creation and cannot be
        // changed afterwards: without a second offer carrying it, `verify_offer_approval`'s entire
        // Some(msg) branch and all of approver_utils is dead code in this harness.
        // -----------------------------------------------------------------------------------
        let mint_appr = ctx
            .create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(USDC_DECIMALS)
            .mint_authority(boss.pubkey())
            .supply(USER_USDC_START * 2)
            .create()
            .unwrap();
        for owner in [
            user_a.pubkey(),
            user_b.pubkey(),
            boss.pubkey(),
            offer_vault_authority,
        ] {
            let amount = if owner == user_a.pubkey() || owner == user_b.pubkey() {
                USER_USDC_START
            } else {
                0
            };
            scout_mk_ata(&mut ctx, &owner, &mint_appr, amount);
        }
        let offer_appr_pda = scout_pda(
            &[SEED_OFFER, mint_appr.as_ref(), mint_onyc.as_ref()],
            &program_id,
        );
        scout_expect_ok(
            "make_offer(appr->onyc, needs_approval)",
            ctx.program(program_id)
                .call(instruction::MakeOffer {
                    fee_basis_points: 100,
                    needs_approval: true,
                    allow_permissionless: false,
                })
                .accounts(accounts::MakeOffer {
                    vault_authority: offer_vault_authority,
                    token_in_mint: mint_appr,
                    token_in_program: SPL_TOKEN_ID,
                    vault_token_in_account: scout_ata(
                        &offer_vault_authority,
                        &mint_appr,
                        &SPL_TOKEN_ID,
                    ),
                    token_out_mint: mint_onyc,
                    offer: offer_appr_pda,
                    state: state_pda,
                    boss: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );
        scout_expect_ok(
            "add_offer_vector(appr->onyc)",
            ctx.program(program_id)
                .call(instruction::AddOfferVector {
                    start_time: None,
                    base_time: now,
                    base_price: 1_000_000_000,
                    apr: 5_000_000,
                    price_fix_duration: 3_600,
                })
                .accounts(accounts::AddOfferVector {
                    offer: offer_appr_pda,
                    token_in_mint: mint_appr,
                    token_out_mint: mint_onyc,
                    state: state_pda,
                    boss: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );

        // -----------------------------------------------------------------------------------
        // 9. The inverse redemption offer: onyc -> usdc.
        //
        // Its `offer` account is derived with the mints SWAPPED (seeds = [OFFER, token_out_mint,
        // token_in_mint]), so it resolves back to the offer created above.
        // -----------------------------------------------------------------------------------
        let redemption_offer_pda = scout_pda(
            &[SEED_REDEMPTION_OFFER, mint_onyc.as_ref(), mint_usdc.as_ref()],
            &program_id,
        );
        scout_expect_ok(
            "make_redemption_offer(onyc->usdc)",
            ctx.program(program_id)
                .call(instruction::MakeRedemptionOffer {
                    fee_basis_points: 50,
                })
                .accounts(accounts::MakeRedemptionOffer {
                    state: state_pda,
                    offer: offer_pda,
                    redemption_vault_authority,
                    token_in_mint: mint_onyc,
                    token_in_program: SPL_TOKEN_ID,
                    vault_token_in_account: scout_ata(
                        &redemption_vault_authority,
                        &mint_onyc,
                        &SPL_TOKEN_ID,
                    ),
                    token_out_mint: mint_usdc,
                    token_out_program: SPL_TOKEN_ID,
                    vault_token_out_account: scout_ata(
                        &redemption_vault_authority,
                        &mint_usdc,
                        &SPL_TOKEN_ID,
                    ),
                    redemption_offer: redemption_offer_pda,
                    signer: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );
        // -----------------------------------------------------------------------------------
        // 10. The REVERSE pair: offer onyc -> usdc, and the redemption offer usdc -> onyc.
        //
        // Everything above redeems INTO usdc, which the program does not control, so
        // `execute_redemption_operations` always takes its transfer-from-vault branch and
        // `mint_tokens` is never reached from a redemption. This pair inverts that: its payout leg
        // is ONyc, whose mint authority the program holds, so fulfilling one of its requests goes
        // through `mint_tokens` — the branch `fulfill_redemption_request.rs:274` hands a hard-coded
        // `token_out_max_supply: 0`, where `take_offer.rs:296` and `mint_to` both pass
        // `state.max_supply`. Without this pair that discrepancy is unobservable.
        // -----------------------------------------------------------------------------------
        let offer_rev_pda = scout_pda(
            &[SEED_OFFER, mint_onyc.as_ref(), mint_usdc.as_ref()],
            &program_id,
        );
        scout_expect_ok(
            "make_offer(onyc->usdc)",
            ctx.program(program_id)
                .call(instruction::MakeOffer {
                    fee_basis_points: 100,
                    needs_approval: false,
                    allow_permissionless: false,
                })
                .accounts(accounts::MakeOffer {
                    vault_authority: offer_vault_authority,
                    token_in_mint: mint_onyc,
                    token_in_program: SPL_TOKEN_ID,
                    vault_token_in_account: scout_ata(&offer_vault_authority, &mint_onyc, &SPL_TOKEN_ID),
                    token_out_mint: mint_usdc,
                    offer: offer_rev_pda,
                    state: state_pda,
                    boss: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );
        scout_expect_ok(
            "add_offer_vector(onyc->usdc)",
            ctx.program(program_id)
                .call(instruction::AddOfferVector {
                    start_time: None,
                    base_time: now,
                    base_price: 1_000_000_000,
                    apr: 5_000_000,
                    price_fix_duration: 3_600,
                })
                .accounts(accounts::AddOfferVector {
                    offer: offer_rev_pda,
                    token_in_mint: mint_onyc,
                    token_out_mint: mint_usdc,
                    state: state_pda,
                    boss: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );

        let redemption_offer_rev_pda = scout_pda(
            &[SEED_REDEMPTION_OFFER, mint_usdc.as_ref(), mint_onyc.as_ref()],
            &program_id,
        );
        scout_expect_ok(
            "make_redemption_offer(usdc->onyc)",
            ctx.program(program_id)
                .call(instruction::MakeRedemptionOffer { fee_basis_points: 50 })
                .accounts(accounts::MakeRedemptionOffer {
                    state: state_pda,
                    offer: offer_rev_pda,
                    redemption_vault_authority,
                    token_in_mint: mint_usdc,
                    token_in_program: SPL_TOKEN_ID,
                    vault_token_in_account: scout_ata(&redemption_vault_authority, &mint_usdc, &SPL_TOKEN_ID),
                    token_out_mint: mint_onyc,
                    token_out_program: SPL_TOKEN_ID,
                    vault_token_out_account: scout_ata(&redemption_vault_authority, &mint_onyc, &SPL_TOKEN_ID),
                    redemption_offer: redemption_offer_rev_pda,
                    signer: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );

        // -----------------------------------------------------------------------------------
        // 11. The Token-2022 TRANSFER-FEE pair: offer usdc -> fee, redemption offer fee -> usdc.
        //
        // `has_transfer_fee` has exactly two call sites in the whole program, both inside
        // `execute_token_operations` (`token_utils.rs:374,378`), which only take_offer and
        // take_offer_permissionless reach. Nothing on the redemption path consults it, and
        // `make_redemption_offer` performs no mint validation at all — so a fee-bearing token_in
        // is an accepted, supported configuration whose deposits arrive short.
        //
        // `create_redemption_request` is permissionless, so unlike every other finding on this
        // target the resulting shortfall needs no privileged signer to occur.
        // -----------------------------------------------------------------------------------
        let mint_fee = scout_mk_t22_fee_mint(
            &mut ctx,
            &boss.pubkey(),
            FEE_DECIMALS,
            USER_USDC_START * 2,
            SCOUT_T22_FEE_BPS,
        );
        for owner in [user_a.pubkey(), user_b.pubkey()] {
            scout_mk_t22_ata(&mut ctx, &owner, &mint_fee, USER_USDC_START);
        }
        // The boss leg receives the offer fee on any take; without it `make_offer` has no
        // destination to `init_if_needed` against a Token-2022 mint.
        scout_mk_t22_ata(&mut ctx, &boss.pubkey(), &mint_fee, 0);

        let offer_fee_pda = scout_pda(
            &[SEED_OFFER, mint_usdc.as_ref(), mint_fee.as_ref()],
            &program_id,
        );
        scout_expect_ok(
            "make_offer(usdc->fee)",
            ctx.program(program_id)
                .call(instruction::MakeOffer {
                    fee_basis_points: 100,
                    needs_approval: false,
                    allow_permissionless: false,
                })
                .accounts(accounts::MakeOffer {
                    vault_authority: offer_vault_authority,
                    token_in_mint: mint_usdc,
                    token_in_program: SPL_TOKEN_ID,
                    vault_token_in_account: scout_ata(&offer_vault_authority, &mint_usdc, &SPL_TOKEN_ID),
                    token_out_mint: mint_fee,
                    offer: offer_fee_pda,
                    state: state_pda,
                    boss: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );

        let redemption_offer_fee_pda = scout_pda(
            &[SEED_REDEMPTION_OFFER, mint_fee.as_ref(), mint_usdc.as_ref()],
            &program_id,
        );
        scout_expect_ok(
            "make_redemption_offer(fee->usdc)",
            ctx.program(program_id)
                .call(instruction::MakeRedemptionOffer { fee_basis_points: 50 })
                .accounts(accounts::MakeRedemptionOffer {
                    state: state_pda,
                    offer: offer_fee_pda,
                    redemption_vault_authority,
                    token_in_mint: mint_fee,
                    token_in_program: SPL_TOKEN_2022_ID,
                    vault_token_in_account: scout_ata(&redemption_vault_authority, &mint_fee, &SPL_TOKEN_2022_ID),
                    token_out_mint: mint_usdc,
                    token_out_program: SPL_TOKEN_ID,
                    vault_token_out_account: scout_ata(&redemption_vault_authority, &mint_usdc, &SPL_TOKEN_ID),
                    redemption_offer: redemption_offer_fee_pda,
                    signer: boss.pubkey(),
                })
                .signers(&[&boss])
                .send(),
        );

        Self {
            ctx,
            program_id,
            payer,
            boss,
            user_a,
            user_b,
            redemption_admin,
            approver,
            mint_usdc,
            mint_onyc,
            mint_play,
            state_pda,
            mint_authority_pda,
            offer_vault_authority,
            redemption_vault_authority,
            permissionless_authority,
            offer_pda,
            redemption_offer_pda,
            offer_rev_pda,
            redemption_offer_rev_pda,
            redemption_vault_onyc: scout_ata(&redemption_vault_authority, &mint_onyc, &SPL_TOKEN_ID),
            scout_p7_reqs: [Pubkey::default(); SCOUT_P7_CAP],
            scout_p7_next: 0,
            scout_p5_offers: {
                let mut a = [Pubkey::default(); SCOUT_OFFER_CAP];
                a[0] = offer_pda;
                a[1] = offer_appr_pda;
                a[2] = offer_rev_pda;
                a
            },
            scout_p5_next: 3,
            scout_p2_reqs: [Pubkey::default(); SCOUT_REQ_CAP],
            scout_p2_next: 0,
            scout_p3_reqs: [Pubkey::default(); SCOUT_REQ_CAP],
            scout_p3_next: 0,
            mint_appr,
            offer_appr_pda,
            mint_fee,
            offer_fee_pda,
            redemption_offer_fee_pda,
            redemption_vault_fee_ata: scout_ata(
                &redemption_vault_authority,
                &mint_fee,
                &SPL_TOKEN_2022_ID,
            ),
            scout_p8_reqs: [Pubkey::default(); SCOUT_REQ_CAP],
            scout_p8_next: 0,
        }
        // SCOUT:SETUP-GLUE:END
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_initialize(&mut self) -> bool {
        let state = self.state_pda;
        let mint_authority = self.mint_authority_pda;
        let offer_vault_authority = self.offer_vault_authority;
        let boss = self.boss.pubkey();
        let program = self.program_id;
        let program_data = scout_pda(&[self.program_id.as_ref()], &BPF_LOADER_UPGRADEABLE_ID);
        let onyc_mint = self.mint_onyc;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::Initialize {  })
            .accounts(accounts::Initialize {
                state: state,
                mint_authority: mint_authority,
                offer_vault_authority: offer_vault_authority,
                boss: boss,
                program_data: program_data,
                onyc_mint: onyc_mint,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:initialize:BEGIN
            // update shadow-ledger state after successful initialize
            // SCOUT:ACTION-HOOK:initialize:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_initialize(&mut self) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_initialize_permissionless_authority(&mut self) -> bool {
        let name: String = String::from("permissionless-1");
        let permissionless_authority = self.permissionless_authority;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::InitializePermissionlessAuthority { name })
            .accounts(accounts::InitializePermissionlessAuthority {
                permissionless_authority: permissionless_authority,
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:initialize_permissionless_authority:BEGIN
            // update shadow-ledger state after successful initialize_permissionless_authority
            // SCOUT:ACTION-HOOK:initialize_permissionless_authority:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_initialize_permissionless_authority(&mut self) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    pub fn action_offer_vault_deposit(&mut self, amount: u64) -> bool {
        let vault_authority = self.offer_vault_authority;
        let token_mint = self.mint_usdc;
        let boss_token_account = scout_ata(&self.boss.pubkey(), &self.mint_usdc, &SPL_TOKEN_ID);
        let vault_token_account = scout_ata(&self.offer_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID);
        let boss = self.boss.pubkey();
        let state = self.state_pda;
        let token_program = SPL_TOKEN_ID;
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::OfferVaultDeposit { amount })
            .accounts(accounts::OfferVaultDeposit {
                vault_authority: vault_authority,
                token_mint: token_mint,
                boss_token_account: boss_token_account,
                vault_token_account: vault_token_account,
                boss: boss,
                state: state,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:offer_vault_deposit:BEGIN
            // update shadow-ledger state after successful offer_vault_deposit
            // SCOUT:ACTION-HOOK:offer_vault_deposit:END
        }
        __scout_success
    }

    pub fn action_offer_vault_withdraw(&mut self, amount: u64) -> bool {
        let vault_authority = self.offer_vault_authority;
        let token_mint = self.mint_usdc;
        let boss_token_account = scout_ata(&self.boss.pubkey(), &self.mint_usdc, &SPL_TOKEN_ID);
        let vault_token_account = scout_ata(&self.offer_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID);
        let boss = self.boss.pubkey();
        let state = self.state_pda;
        let token_program = SPL_TOKEN_ID;
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::OfferVaultWithdraw { amount })
            .accounts(accounts::OfferVaultWithdraw {
                vault_authority: vault_authority,
                token_mint: token_mint,
                boss_token_account: boss_token_account,
                vault_token_account: vault_token_account,
                boss: boss,
                state: state,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:offer_vault_withdraw:BEGIN
            // update shadow-ledger state after successful offer_vault_withdraw
            // SCOUT:ACTION-HOOK:offer_vault_withdraw:END
        }
        __scout_success
    }

    pub fn action_redemption_vault_deposit(&mut self, amount: u64) -> bool {
        let redemption_vault_authority = self.redemption_vault_authority;
        let token_mint = self.pick_vault_mint(amount);
        let boss_token_account = scout_ata(&self.boss.pubkey(), &self.pick_vault_mint(amount), &SPL_TOKEN_ID);
        let vault_token_account = scout_ata(&self.redemption_vault_authority, &self.pick_vault_mint(amount), &SPL_TOKEN_ID);
        let boss = self.boss.pubkey();
        let state = self.state_pda;
        let token_program = SPL_TOKEN_ID;
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::RedemptionVaultDeposit { amount })
            .accounts(accounts::RedemptionVaultDeposit {
                redemption_vault_authority: redemption_vault_authority,
                token_mint: token_mint,
                boss_token_account: boss_token_account,
                vault_token_account: vault_token_account,
                boss: boss,
                state: state,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:redemption_vault_deposit:BEGIN
            // update shadow-ledger state after successful redemption_vault_deposit
            // SCOUT:ACTION-HOOK:redemption_vault_deposit:END
        }
        __scout_success
    }

    pub fn action_redemption_vault_withdraw(&mut self, amount: u64) -> bool {
        let redemption_vault_authority = self.redemption_vault_authority;
        let token_mint = self.pick_vault_mint(amount);
        let boss_token_account = scout_ata(&self.boss.pubkey(), &self.pick_vault_mint(amount), &SPL_TOKEN_ID);
        let vault_token_account = scout_ata(&self.redemption_vault_authority, &self.pick_vault_mint(amount), &SPL_TOKEN_ID);
        let boss = self.boss.pubkey();
        let state = self.state_pda;
        let token_program = SPL_TOKEN_ID;
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::RedemptionVaultWithdraw { amount })
            .accounts(accounts::RedemptionVaultWithdraw {
                redemption_vault_authority: redemption_vault_authority,
                token_mint: token_mint,
                boss_token_account: boss_token_account,
                vault_token_account: vault_token_account,
                boss: boss,
                state: state,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:redemption_vault_withdraw:BEGIN
            // update shadow-ledger state after successful redemption_vault_withdraw
            // SCOUT:ACTION-HOOK:redemption_vault_withdraw:END
        }
        __scout_success
    }

    pub fn action_make_offer(&mut self, fee_basis_points: u16, needs_approval: bool, allow_permissionless: bool) -> bool {
        let vault_authority = self.offer_vault_authority;
        let token_in_mint = self.make_offer_pair(fee_basis_points).0;
        let token_in_program = SPL_TOKEN_ID;
        let vault_token_in_account = scout_ata(&self.offer_vault_authority, &self.make_offer_pair(fee_basis_points).0, &SPL_TOKEN_ID);
        let token_out_mint = self.make_offer_pair(fee_basis_points).1;
        let offer = self.make_offer_pda_for(fee_basis_points);
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::MakeOffer { fee_basis_points, needs_approval, allow_permissionless })
            .accounts(accounts::MakeOffer {
                vault_authority: vault_authority,
                token_in_mint: token_in_mint,
                token_in_program: token_in_program,
                vault_token_in_account: vault_token_in_account,
                token_out_mint: token_out_mint,
                offer: offer,
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:make_offer:BEGIN
            // Feeds the offer registry that BOTH P-0005 and P-0006 read. Their reviewed hooks
            // are identical apart from the gating id (under SCOUT_CHECK_ONLY exactly one runs);
            // this harness never sets that, so registering once keeps the ring at full depth.
            scout_run_property!("P-0005", {
                self.scout_p5_offers[self.scout_p5_next % SCOUT_OFFER_CAP] = offer;
                self.scout_p5_next = self.scout_p5_next.saturating_add(1);
            });
            // SCOUT:ACTION-HOOK:make_offer:END
        }
        __scout_success
    }

    pub fn action_add_offer_vector(&mut self, base_time: u64, base_price: u64, apr: u64, price_fix_duration: u64) -> bool {
        let start_time: Option<u64> = None;
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::AddOfferVector { start_time, base_time, base_price, apr, price_fix_duration })
            .accounts(accounts::AddOfferVector {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:add_offer_vector:BEGIN
            // update shadow-ledger state after successful add_offer_vector
            // SCOUT:ACTION-HOOK:add_offer_vector:END
        }
        __scout_success
    }

    pub fn action_delete_offer_vector(&mut self, vector_start_time: u64) -> bool {
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::DeleteOfferVector { vector_start_time })
            .accounts(accounts::DeleteOfferVector {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:delete_offer_vector:BEGIN
            // update shadow-ledger state after successful delete_offer_vector
            // SCOUT:ACTION-HOOK:delete_offer_vector:END
        }
        __scout_success
    }

    pub fn action_delete_all_offer_vectors(&mut self) -> bool {
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::DeleteAllOfferVectors {  })
            .accounts(accounts::DeleteAllOfferVectors {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:delete_all_offer_vectors:BEGIN
            // update shadow-ledger state after successful delete_all_offer_vectors
            // SCOUT:ACTION-HOOK:delete_all_offer_vectors:END
        }
        __scout_success
    }

    pub fn action_update_offer_fee(&mut self, new_fee_basis_points: u16) -> bool {
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::UpdateOfferFee { new_fee_basis_points })
            .accounts(accounts::UpdateOfferFee {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:update_offer_fee:BEGIN
            // update shadow-ledger state after successful update_offer_fee
            // SCOUT:ACTION-HOOK:update_offer_fee:END
        }
        __scout_success
    }

    pub fn action_take_offer(&mut self, token_in_amount: u64) -> bool {
        let approval_message: Option<onreapp::types::ApprovalMessage> = None;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let vault_authority = self.offer_vault_authority;
        let vault_token_in_account = scout_ata(&self.offer_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID);
        let vault_token_out_account = scout_ata(&self.offer_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let token_in_mint = self.mint_usdc;
        let token_in_program = SPL_TOKEN_ID;
        let token_out_mint = self.mint_onyc;
        let token_out_program = SPL_TOKEN_ID;
        let user_token_in_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_usdc, &SPL_TOKEN_ID);
        let user_token_out_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_onyc, &SPL_TOKEN_ID);
        let boss_token_in_account = scout_ata(&self.boss.pubkey(), &self.mint_usdc, &SPL_TOKEN_ID);
        let mint_authority = self.mint_authority_pda;
        let instructions_sysvar = INSTRUCTIONS_SYSVAR_ID;
        let __scout_signer_user = self.pick_user(token_in_amount);
        let user = __scout_signer_user.pubkey();
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::TakeOffer { token_in_amount, approval_message })
            .accounts(accounts::TakeOffer {
                offer: offer,
                state: state,
                boss: boss,
                vault_authority: vault_authority,
                vault_token_in_account: vault_token_in_account,
                vault_token_out_account: vault_token_out_account,
                token_in_mint: token_in_mint,
                token_in_program: token_in_program,
                token_out_mint: token_out_mint,
                token_out_program: token_out_program,
                user_token_in_account: user_token_in_account,
                user_token_out_account: user_token_out_account,
                boss_token_in_account: boss_token_in_account,
                mint_authority: mint_authority,
                user: user,
            })
            .signers(&[&*self.payer, &__scout_signer_user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:take_offer:BEGIN
            // update shadow-ledger state after successful take_offer
            // SCOUT:ACTION-HOOK:take_offer:END
        }
        __scout_success
    }

    pub fn action_take_offer_permissionless(&mut self, token_in_amount: u64) -> bool {
        let approval_message: Option<onreapp::types::ApprovalMessage> = None;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let vault_authority = self.offer_vault_authority;
        let vault_token_in_account = scout_ata(&self.offer_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID);
        let vault_token_out_account = scout_ata(&self.offer_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let permissionless_authority = self.permissionless_authority;
        let permissionless_token_in_account = scout_ata(&self.permissionless_authority, &self.mint_usdc, &SPL_TOKEN_ID);
        let permissionless_token_out_account = scout_ata(&self.permissionless_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let token_in_mint = self.mint_usdc;
        let token_in_program = SPL_TOKEN_ID;
        let token_out_mint = self.mint_onyc;
        let token_out_program = SPL_TOKEN_ID;
        let user_token_in_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_usdc, &SPL_TOKEN_ID);
        let user_token_out_account = scout_ata(&self.pick_user_pk(token_in_amount), &self.mint_onyc, &SPL_TOKEN_ID);
        let boss_token_in_account = scout_ata(&self.boss.pubkey(), &self.mint_usdc, &SPL_TOKEN_ID);
        let mint_authority = self.mint_authority_pda;
        let instructions_sysvar = INSTRUCTIONS_SYSVAR_ID;
        let __scout_signer_user = self.pick_user(token_in_amount);
        let user = __scout_signer_user.pubkey();
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::TakeOfferPermissionless { token_in_amount, approval_message })
            .accounts(accounts::TakeOfferPermissionless {
                offer: offer,
                state: state,
                boss: boss,
                vault_authority: vault_authority,
                vault_token_in_account: vault_token_in_account,
                vault_token_out_account: vault_token_out_account,
                permissionless_authority: permissionless_authority,
                permissionless_token_in_account: permissionless_token_in_account,
                permissionless_token_out_account: permissionless_token_out_account,
                token_in_mint: token_in_mint,
                token_in_program: token_in_program,
                token_out_mint: token_out_mint,
                token_out_program: token_out_program,
                user_token_in_account: user_token_in_account,
                user_token_out_account: user_token_out_account,
                boss_token_in_account: boss_token_in_account,
                mint_authority: mint_authority,
                user: user,
            })
            .signers(&[&*self.payer, &__scout_signer_user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:take_offer_permissionless:BEGIN
            // update shadow-ledger state after successful take_offer_permissionless
            // SCOUT:ACTION-HOOK:take_offer_permissionless:END
        }
        __scout_success
    }

    pub fn action_propose_boss(&mut self) -> bool {
        let new_boss: Pubkey = self.boss.pubkey();
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::ProposeBoss { new_boss })
            .accounts(accounts::ProposeBoss {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:propose_boss:BEGIN
            // update shadow-ledger state after successful propose_boss
            // SCOUT:ACTION-HOOK:propose_boss:END
        }
        __scout_success
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_accept_boss(&mut self) -> bool {
        let state = self.state_pda;
        let new_boss = self.payer.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::AcceptBoss {  })
            .accounts(accounts::AcceptBoss {
                state: state,
                new_boss: new_boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:accept_boss:BEGIN
            // update shadow-ledger state after successful accept_boss
            // SCOUT:ACTION-HOOK:accept_boss:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_accept_boss(&mut self) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_add_admin(&mut self) -> bool {
        let new_admin: Pubkey = self.user_a.pubkey();
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::AddAdmin { new_admin })
            .accounts(accounts::AddAdmin {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:add_admin:BEGIN
            // update shadow-ledger state after successful add_admin
            // SCOUT:ACTION-HOOK:add_admin:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_add_admin(&mut self) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_remove_admin(&mut self) -> bool {
        let admin_to_remove: Pubkey = self.user_a.pubkey();
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::RemoveAdmin { admin_to_remove })
            .accounts(accounts::RemoveAdmin {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:remove_admin:BEGIN
            // update shadow-ledger state after successful remove_admin
            // SCOUT:ACTION-HOOK:remove_admin:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_remove_admin(&mut self) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_clear_admins(&mut self) -> bool {
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::ClearAdmins {  })
            .accounts(accounts::ClearAdmins {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:clear_admins:BEGIN
            // update shadow-ledger state after successful clear_admins
            // SCOUT:ACTION-HOOK:clear_admins:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_clear_admins(&mut self) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    pub fn action_transfer_mint_authority_to_program(&mut self) -> bool {
        let boss = self.boss.pubkey();
        let state = self.state_pda;
        let mint = self.mint_play;
        let mint_authority = self.mint_authority_pda;
        let token_program = SPL_TOKEN_ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::TransferMintAuthorityToProgram {  })
            .accounts(accounts::TransferMintAuthorityToProgram {
                boss: boss,
                state: state,
                mint: mint,
                mint_authority: mint_authority,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:transfer_mint_authority_to_program:BEGIN
            // update shadow-ledger state after successful transfer_mint_authority_to_program
            // SCOUT:ACTION-HOOK:transfer_mint_authority_to_program:END
        }
        __scout_success
    }

    pub fn action_transfer_mint_authority_to_boss(&mut self) -> bool {
        let boss = self.boss.pubkey();
        let state = self.state_pda;
        let mint = self.mint_play;
        let mint_authority = self.mint_authority_pda;
        let token_program = SPL_TOKEN_ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::TransferMintAuthorityToBoss {  })
            .accounts(accounts::TransferMintAuthorityToBoss {
                boss: boss,
                state: state,
                mint: mint,
                mint_authority: mint_authority,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:transfer_mint_authority_to_boss:BEGIN
            // update shadow-ledger state after successful transfer_mint_authority_to_boss
            // SCOUT:ACTION-HOOK:transfer_mint_authority_to_boss:END
        }
        __scout_success
    }

    pub fn action_set_kill_switch(&mut self, enable: bool) -> bool {
        let state = self.state_pda;
        let signer = self.payer.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::SetKillSwitch { enable })
            .accounts(accounts::SetKillSwitch {
                state: state,
                signer: signer,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:set_kill_switch:BEGIN
            // update shadow-ledger state after successful set_kill_switch
            // SCOUT:ACTION-HOOK:set_kill_switch:END
        }
        __scout_success
    }

    pub fn action_set_onyc_mint(&mut self) -> bool {
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let onyc_mint = self.mint_onyc;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::SetOnycMint {  })
            .accounts(accounts::SetOnycMint {
                state: state,
                boss: boss,
                onyc_mint: onyc_mint,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:set_onyc_mint:BEGIN
            // update shadow-ledger state after successful set_onyc_mint
            // SCOUT:ACTION-HOOK:set_onyc_mint:END
        }
        __scout_success
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_set_redemption_admin(&mut self) -> bool {
        let new_redemption_admin: Pubkey = self.redemption_admin.pubkey();
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::SetRedemptionAdmin { new_redemption_admin })
            .accounts(accounts::SetRedemptionAdmin {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:set_redemption_admin:BEGIN
            // update shadow-ledger state after successful set_redemption_admin
            // SCOUT:ACTION-HOOK:set_redemption_admin:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_set_redemption_admin(&mut self) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    pub fn action_mint_to(&mut self, amount: u64) -> bool {
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let onyc_mint = self.mint_onyc;
        let boss_onyc_account = scout_ata(&self.boss.pubkey(), &self.mint_onyc, &SPL_TOKEN_ID);
        let mint_authority = self.mint_authority_pda;
        let token_program = SPL_TOKEN_ID;
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::MintTo { amount })
            .accounts(accounts::MintTo {
                state: state,
                boss: boss,
                onyc_mint: onyc_mint,
                boss_onyc_account: boss_onyc_account,
                mint_authority: mint_authority,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:mint_to:BEGIN
            // update shadow-ledger state after successful mint_to
            // SCOUT:ACTION-HOOK:mint_to:END
        }
        __scout_success
    }

    pub fn action_get_nav(&mut self) -> bool {
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::GetNav {  })
            .accounts(accounts::GetNav {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:get_nav:BEGIN
            // update shadow-ledger state after successful get_nav
            // SCOUT:ACTION-HOOK:get_nav:END
        }
        __scout_success
    }

    pub fn action_get_apy(&mut self) -> bool {
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::GetApy {  })
            .accounts(accounts::GetApy {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:get_apy:BEGIN
            // update shadow-ledger state after successful get_apy
            // SCOUT:ACTION-HOOK:get_apy:END
        }
        __scout_success
    }

    pub fn action_get_nav_adjustment(&mut self) -> bool {
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::GetNavAdjustment {  })
            .accounts(accounts::GetNavAdjustment {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:get_nav_adjustment:BEGIN
            // update shadow-ledger state after successful get_nav_adjustment
            // SCOUT:ACTION-HOOK:get_nav_adjustment:END
        }
        __scout_success
    }

    pub fn action_get_tvl(&mut self) -> bool {
        let token_in_mint = self.mint_usdc;
        let token_out_mint = self.mint_onyc;
        let vault_authority = self.offer_vault_authority;
        let vault_token_out_account = scout_ata(&self.offer_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let token_out_program = SPL_TOKEN_ID;
        let offer = self.offer_pda;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::GetTvl {  })
            .accounts(accounts::GetTvl {
                offer: offer,
                token_in_mint: token_in_mint,
                token_out_mint: token_out_mint,
                vault_authority: vault_authority,
                vault_token_out_account: vault_token_out_account,
                token_out_program: token_out_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:get_tvl:BEGIN
            // update shadow-ledger state after successful get_tvl
            // SCOUT:ACTION-HOOK:get_tvl:END
        }
        __scout_success
    }

    pub fn action_get_circulating_supply(&mut self) -> bool {
        let onyc_mint = self.mint_onyc;
        let state = self.state_pda;
        let vault_authority = self.offer_vault_authority;
        let onyc_vault_account = scout_ata(&self.offer_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let token_program = SPL_TOKEN_ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::GetCirculatingSupply {  })
            .accounts(accounts::GetCirculatingSupply {
                onyc_mint: onyc_mint,
                state: state,
                vault_authority: vault_authority,
                onyc_vault_account: onyc_vault_account,
                token_program: token_program,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:get_circulating_supply:BEGIN
            // update shadow-ledger state after successful get_circulating_supply
            // SCOUT:ACTION-HOOK:get_circulating_supply:END
        }
        __scout_success
    }

    pub fn action_add_approver(&mut self) -> bool {
        let approver: Pubkey = self.approver.pubkey();
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::AddApprover { approver })
            .accounts(accounts::AddApprover {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:add_approver:BEGIN
            // update shadow-ledger state after successful add_approver
            // SCOUT:ACTION-HOOK:add_approver:END
        }
        __scout_success
    }

    pub fn action_remove_approver(&mut self) -> bool {
        let approver: Pubkey = self.approver.pubkey();
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::RemoveApprover { approver })
            .accounts(accounts::RemoveApprover {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:remove_approver:BEGIN
            // update shadow-ledger state after successful remove_approver
            // SCOUT:ACTION-HOOK:remove_approver:END
        }
        __scout_success
    }

    #[cfg(feature = "admin_actions")]
    pub fn action_configure_max_supply(&mut self, max_supply: u64) -> bool {
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::ConfigureMaxSupply { max_supply })
            .accounts(accounts::ConfigureMaxSupply {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:configure_max_supply:BEGIN
            // update shadow-ledger state after successful configure_max_supply
            // SCOUT:ACTION-HOOK:configure_max_supply:END
        }
        __scout_success
    }
    #[cfg(not(feature = "admin_actions"))]
    pub fn action_configure_max_supply(&mut self, max_supply: u64) -> bool {
        // disabled: build with --features admin_actions to enable
        false
    }

    pub fn action_close_state(&mut self) -> bool {
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::CloseState {  })
            .accounts(accounts::CloseState {
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:close_state:BEGIN
            // Nothing to record. close_state deallocates the State PDA by design; recovery is
            // exposed as `action_scout_rebuild_state` (SCOUT:EXTRA-ACTIONS) rather than done here,
            // because a hook region may hold only pure assignments — no calls, no conditionals.
            // SCOUT:ACTION-HOOK:close_state:END
        }
        __scout_success
    }

    pub fn action_make_redemption_offer(&mut self, fee_basis_points: u16) -> bool {
        let state = self.state_pda;
        let redemption_vault_authority = self.redemption_vault_authority;
        let token_in_mint = self.mint_onyc;
        let token_in_program = SPL_TOKEN_ID;
        let vault_token_in_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let token_out_mint = self.mint_play;
        let token_out_program = SPL_TOKEN_ID;
        let vault_token_out_account = scout_ata(&self.redemption_vault_authority, &self.mint_play, &SPL_TOKEN_ID);
        let redemption_offer = scout_pda(&[SEED_REDEMPTION_OFFER, self.mint_onyc.as_ref(), self.mint_play.as_ref()], &self.program_id);
        let __scout_signer_signer = self.redemption_admin.insecure_clone();
        let signer = __scout_signer_signer.pubkey();
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let offer = scout_pda(&[SEED_OFFER, self.mint_play.as_ref(), self.mint_onyc.as_ref()], &self.program_id);
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::MakeRedemptionOffer { fee_basis_points })
            .accounts(accounts::MakeRedemptionOffer {
                state: state,
                offer: offer,
                redemption_vault_authority: redemption_vault_authority,
                token_in_mint: token_in_mint,
                token_in_program: token_in_program,
                vault_token_in_account: vault_token_in_account,
                token_out_mint: token_out_mint,
                token_out_program: token_out_program,
                vault_token_out_account: vault_token_out_account,
                redemption_offer: redemption_offer,
                signer: signer,
            })
            .signers(&[&*self.payer, &__scout_signer_signer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:make_redemption_offer:BEGIN
            // update shadow-ledger state after successful make_redemption_offer
            // SCOUT:ACTION-HOOK:make_redemption_offer:END
        }
        __scout_success
    }

    pub fn action_create_redemption_request(&mut self, amount: u64) -> bool {
        let state = self.state_pda;
        let redemption_offer = self.redemption_offer_pda;
        let redemption_request = self.next_request_pda();
        let __scout_signer_redeemer = self.pick_user(amount);
        let redeemer = __scout_signer_redeemer.pubkey();
        let redemption_vault_authority = self.redemption_vault_authority;
        let token_in_mint = self.mint_onyc;
        let redeemer_token_account = scout_ata(&self.pick_user_pk(amount), &self.mint_onyc, &SPL_TOKEN_ID);
        let vault_token_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let token_program = SPL_TOKEN_ID;
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::CreateRedemptionRequest { amount })
            .accounts(accounts::CreateRedemptionRequest {
                state: state,
                redemption_offer: redemption_offer,
                redemption_request: redemption_request,
                redeemer: redeemer,
                redemption_vault_authority: redemption_vault_authority,
                token_in_mint: token_in_mint,
                redeemer_token_account: redeemer_token_account,
                vault_token_account: vault_token_account,
                token_program: token_program,
            })
            .signers(&[&*self.payer, &__scout_signer_redeemer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:create_redemption_request:BEGIN
            // Each property keeps its OWN registry: an isolated single-property replay runs
            // exactly one of these hooks, so a shared counter would advance a different number of
            // times depending on which property was selected.
            scout_run_property!("P-0002", {
                self.scout_p2_reqs[self.scout_p2_next % SCOUT_REQ_CAP] = redemption_request;
                self.scout_p2_next = self.scout_p2_next.saturating_add(1);
            });
            scout_run_property!("P-0003", {
                self.scout_p3_reqs[self.scout_p3_next % SCOUT_REQ_CAP] = redemption_request;
                self.scout_p3_next = self.scout_p3_next.saturating_add(1);
                self.scout_p7_reqs[self.scout_p7_next % SCOUT_P7_CAP] = redemption_request;
                self.scout_p7_next = self.scout_p7_next.saturating_add(1);
            });
            // P-0007's block is retired, but its registry stays fed under P-0003's gate so the
            // pooled-solvency test (c5_pool_stays_solvent_without_the_drain) still has its subject.
            // SCOUT:ACTION-HOOK:create_redemption_request:END
        }
        __scout_success
    }

    pub fn action_fulfill_redemption_request(&mut self) -> bool {
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let offer = self.offer_pda;
        let redemption_offer = self.redemption_offer_pda;
        let redemption_request = self.oldest_request_pda();
        let redemption_vault_authority = self.redemption_vault_authority;
        let vault_token_in_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let vault_token_out_account = scout_ata(&self.redemption_vault_authority, &self.mint_usdc, &SPL_TOKEN_ID);
        let token_in_mint = self.mint_onyc;
        let token_in_program = SPL_TOKEN_ID;
        let token_out_mint = self.mint_usdc;
        let token_out_program = SPL_TOKEN_ID;
        let user_token_out_account = scout_ata(&self.oldest_request_redeemer(), &self.mint_usdc, &SPL_TOKEN_ID);
        let boss_token_in_account = scout_ata(&self.boss.pubkey(), &self.mint_onyc, &SPL_TOKEN_ID);
        let mint_authority = self.mint_authority_pda;
        let redeemer = self.oldest_request_redeemer();
        let __scout_signer_redemption_admin = self.redemption_admin.insecure_clone();
        let redemption_admin = __scout_signer_redemption_admin.pubkey();
        let associated_token_program = ATA_PROGRAM_ID;
        let system_program = system_program::ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::FulfillRedemptionRequest {  })
            .accounts(accounts::FulfillRedemptionRequest {
                state: state,
                boss: boss,
                offer: offer,
                redemption_offer: redemption_offer,
                redemption_request: redemption_request,
                redemption_vault_authority: redemption_vault_authority,
                vault_token_in_account: vault_token_in_account,
                vault_token_out_account: vault_token_out_account,
                token_in_mint: token_in_mint,
                token_in_program: token_in_program,
                token_out_mint: token_out_mint,
                token_out_program: token_out_program,
                user_token_out_account: user_token_out_account,
                boss_token_in_account: boss_token_in_account,
                mint_authority: mint_authority,
                redeemer: redeemer,
                redemption_admin: redemption_admin,
            })
            .signers(&[&*self.payer, &__scout_signer_redemption_admin])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:fulfill_redemption_request:BEGIN
            // No shadow ledger to maintain — every property below walks the request
            // accounts themselves, so "the account still exists" IS "the request is open".
            // SCOUT:ACTION-HOOK:fulfill_redemption_request:END
        }
        __scout_success
    }

    pub fn action_cancel_redemption_request(&mut self) -> bool {
        let state = self.state_pda;
        let redemption_offer = self.redemption_offer_pda;
        let redemption_request = self.oldest_request_pda();
        let __scout_signer_signer = self.redemption_admin.insecure_clone();
        let signer = __scout_signer_signer.pubkey();
        let redeemer = self.oldest_request_redeemer();
        let redemption_admin = self.redemption_admin.pubkey();
        let redemption_vault_authority = self.redemption_vault_authority;
        let token_in_mint = self.mint_onyc;
        let vault_token_account = scout_ata(&self.redemption_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID);
        let redeemer_token_account = scout_ata(&self.oldest_request_redeemer(), &self.mint_onyc, &SPL_TOKEN_ID);
        let token_program = SPL_TOKEN_ID;
        let system_program = system_program::ID;
        let associated_token_program = ATA_PROGRAM_ID;
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::CancelRedemptionRequest {  })
            .accounts(accounts::CancelRedemptionRequest {
                state: state,
                redemption_offer: redemption_offer,
                redemption_request: redemption_request,
                signer: signer,
                redeemer: redeemer,
                redemption_admin: redemption_admin,
                redemption_vault_authority: redemption_vault_authority,
                token_in_mint: token_in_mint,
                vault_token_account: vault_token_account,
                redeemer_token_account: redeemer_token_account,
                token_program: token_program,
            })
            .signers(&[&*self.payer, &__scout_signer_signer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:cancel_redemption_request:BEGIN
            // No shadow ledger to maintain — every property below walks the request
            // accounts themselves, so "the account still exists" IS "the request is open".
            // SCOUT:ACTION-HOOK:cancel_redemption_request:END
        }
        __scout_success
    }

    pub fn action_update_redemption_offer_fee(&mut self, new_fee_basis_points: u16) -> bool {
        let redemption_offer = self.redemption_offer_pda;
        let state = self.state_pda;
        let boss = self.boss.pubkey();
        let __scout_success = self.ctx
            .program(self.program_id)
            .call(instruction::UpdateRedemptionOfferFee { new_fee_basis_points })
            .accounts(accounts::UpdateRedemptionOfferFee {
                redemption_offer: redemption_offer,
                state: state,
                boss: boss,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if __scout_success {
            // SCOUT:ACTION-HOOK:update_redemption_offer_fee:BEGIN
            // update shadow-ledger state after successful update_redemption_offer_fee
            // SCOUT:ACTION-HOOK:update_redemption_offer_fee:END
        }
        __scout_success
    }

    // SCOUT:EXTRA-ACTIONS:BEGIN
    /// Move the clock forward. NOT an IDL instruction — no real program exposes "advance time",
    /// but essentially every guard in this one reads `Clock::get()`.
    ///
    /// Without this the harness quotes a single price forever: `calculate_step_price_at` snaps to
    /// the end of the current `price_fix_duration` window, `find_active_vector_at` selects by
    /// `start_time <= now`, and `add_offer_vector` refuses any `start_time` at or below the latest
    /// existing one. A frozen clock therefore deletes the whole "value moved between two user
    /// actions" bug class AND makes a second vector unaddable, which is exactly where the
    /// interesting pricing behaviour lives.
    pub fn action_scout_advance_time(&mut self, seconds: u32) -> bool {
        // Bounded so the fuzzer explores real durations (sub-window, multi-window, multi-year)
        // instead of spending its budget on timestamps that overflow the price math immediately.
        let delta = 1i64 + (seconds as i64 % 40_000_000);
        let now = scout_now(&self.ctx) as i64;
        scout_set_time(&mut self.ctx, now.saturating_add(delta));
        self.ctx.advance_slots(1);
        true
    }

    /// Price the self-referential onyc->onyc offer, if one exists.
    ///
    /// Deliberately does NOT create it. The only creator is the generated `make_offer` action,
    /// whose (token_in, token_out) pair the fuzzer selects via `make_offer_pair` — so the state
    /// P-0005 forbids is reached through the real IDL instruction, and a minimized counterexample
    /// names `make_offer` rather than a bespoke harness action.
    ///
    /// Priced below 1.0, which is an ordinary `base_price` for a pair where one unit of the input
    /// buys more than one of the output; it only becomes a money printer because both legs are the
    /// same token.
    pub fn action_scout_price_same_mint_offer(&mut self, price: u64) -> bool {
        let m = self.mint_onyc;
        let offer = scout_pda(&[SEED_OFFER, m.as_ref(), m.as_ref()], &self.program_id);
        let boss = self.boss.insecure_clone();
        let state_pda = self.state_pda;
        let now = scout_now(&self.ctx);
        // `.max(1)` rather than `1 + ..` so a caller asking for exactly 0.5 gets 500_000_000.
        let base_price = (price % 2_000_000_000).max(1);
        self.ctx
            .program(self.program_id)
            .call(instruction::AddOfferVector {
                start_time: None,
                base_time: now,
                base_price,
                apr: 0,
                price_fix_duration: 3_600,
            })
            .accounts(accounts::AddOfferVector {
                offer,
                token_in_mint: m,
                token_out_mint: m,
                state: state_pda,
                boss: boss.pubkey(),
            })
            .signers(&[&boss])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Take the same-mint offer. Separate from the generated action, whose bindings pin it to the
    /// usdc -> onyc pair.
    pub fn action_scout_take_same_mint_offer(&mut self, amount: u64, sel: u8) -> bool {
        let m = self.mint_onyc;
        let offer = scout_pda(&[SEED_OFFER, m.as_ref(), m.as_ref()], &self.program_id);
        let user_kp = self.pick_user(sel as u64);
        let user = user_kp.pubkey();
        let amount = if sel & 4 != 0 { amount } else { amount % (USER_ONYC_START / 4) + 1 };
        let va = self.offer_vault_authority;
        let (state_pda, boss_pk, ma) = (self.state_pda, self.boss.pubkey(), self.mint_authority_pda);
        let vault_ata = scout_ata(&va, &m, &SPL_TOKEN_ID);
        let uata = scout_ata(&user, &m, &SPL_TOKEN_ID);
        let boss_ata = scout_ata(&boss_pk, &m, &SPL_TOKEN_ID);
        self.ctx
            .program(self.program_id)
            .call(instruction::TakeOffer { token_in_amount: amount, approval_message: None })
            .accounts(accounts::TakeOffer {
                offer,
                state: state_pda,
                boss: boss_pk,
                vault_authority: va,
                vault_token_in_account: vault_ata,
                vault_token_out_account: vault_ata,
                token_in_mint: m,
                token_in_program: SPL_TOKEN_ID,
                token_out_mint: m,
                token_out_program: SPL_TOKEN_ID,
                user_token_in_account: uata,
                user_token_out_account: uata,
                boss_token_in_account: boss_ata,
                mint_authority: ma,
                user,
            })
            .signers(&[&user_kp])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Configure `state.max_supply` — the ONyc minting cap.
    ///
    /// `configure_max_supply` is admin-gated out of the generated pool (it reconfigures the world),
    /// so without this the cap is 0 forever and every `max_supply > 0` branch of `mint_tokens`
    /// (token_utils.rs:234-245) is dead code.
    ///
    /// The cap is ALWAYS set at or above the current supply. `configure_max_supply` itself performs
    /// no such check, so a lower cap is legal on-chain — but a harness that set one would make
    /// `supply > max_supply` true immediately and by construction, and P-0004 would be reporting the
    /// harness's own choice rather than a mint that overshot. Fixing the floor here means any later
    /// excess was necessarily produced by minting, which is exactly the question the property asks.
    pub fn action_scout_configure_max_supply(&mut self, headroom: u64) -> bool {
        let supply = match self.onyc_supply() {
            Some(v) => v,
            None => return false,
        };
        // Headroom spans zero (cap exactly at supply: any mint at all overshoots) up to a slack
        // large enough that ordinary activity stays under it.
        let max_supply = supply.saturating_add(headroom % 1_000_000_000_000);
        let boss = self.boss.insecure_clone();
        self.ctx
            .program(self.program_id)
            .call(instruction::ConfigureMaxSupply { max_supply })
            .accounts(accounts::ConfigureMaxSupply { state: self.state_pda, boss: boss.pubkey() })
            .signers(&[&boss])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Open a redemption request against the `onyc -> play` redemption offer that
    /// `action_make_redemption_offer` creates.
    ///
    /// Its token_in is ONyc, exactly like the offer `setup()` built — and because
    /// `seeds::REDEMPTION_OFFER_VAULT_AUTHORITY` carries no per-offer discriminator, BOTH offers'
    /// collateral lands in the same token account. Without this action only one offer ever funds
    /// that vault and P-0007 degenerates into P-0002; with it, the pooled-solvency question is
    /// actually posed.
    pub fn action_scout_create_request_play(&mut self, amount: u64, sel: u8) -> bool {
        let ro = scout_pda(
            &[SEED_REDEMPTION_OFFER, self.mint_onyc.as_ref(), self.mint_play.as_ref()],
            &self.program_id,
        );
        let id = match self.request_counter_of(&ro) {
            Some(v) => v,
            None => return false, // the offer does not exist yet
        };
        let user_kp = self.pick_user(sel as u64);
        let user = user_kp.pubkey();
        let amount = if sel & 4 != 0 { amount } else { amount % (USER_ONYC_START / 8) + 1 };
        let request = self.request_pda_of(&ro, id);
        let rva = self.redemption_vault_authority;
        let (state_pda, mint_onyc) = (self.state_pda, self.mint_onyc);
        let redeemer_ata = scout_ata(&user, &mint_onyc, &SPL_TOKEN_ID);
        let vault_ata = scout_ata(&rva, &mint_onyc, &SPL_TOKEN_ID);
        let ok = self
            .ctx
            .program(self.program_id)
            .call(instruction::CreateRedemptionRequest { amount })
            .accounts(accounts::CreateRedemptionRequest {
                state: state_pda,
                redemption_offer: ro,
                redemption_request: request,
                redeemer: user,
                redemption_vault_authority: rva,
                token_in_mint: mint_onyc,
                redeemer_token_account: redeemer_ata,
                vault_token_account: vault_ata,
                token_program: SPL_TOKEN_ID,
            })
            .signers(&[&user_kp])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        if ok {
            // kept fed even with P-0007 retired: c5_pool_stays_solvent_without_the_drain reads it
            self.scout_p7_reqs[self.scout_p7_next % SCOUT_P7_CAP] = request;
            self.scout_p7_next = self.scout_p7_next.saturating_add(1);
        }
        ok
    }

    /// Open a redemption request against the REVERSE offer (usdc in, ONyc out).
    ///
    /// Separate from the generated action, which the bindings pin to the forward offer. Fulfilling
    /// one of these is the only path in the harness that reaches `mint_tokens` from a redemption.
    pub fn action_scout_create_request_rev(&mut self, amount: u64, sel: u8) -> bool {
        let ro = self.redemption_offer_rev_pda;
        let id = match self.request_counter_of(&ro) {
            Some(v) => v,
            None => return false,
        };
        let user_kp = self.pick_user(sel as u64);
        let user = user_kp.pubkey();
        // Bounded so the transfer is usually affordable; bit 2 leaves a quarter of draws raw so the
        // insufficient-funds and overflow paths stay reachable.
        let amount = if sel & 4 != 0 { amount } else { amount % (USER_USDC_START / 4) + 1 };
        let request = self.request_pda_of(&ro, id);
        let rva = self.redemption_vault_authority;
        let redeemer_ata = scout_ata(&user, &self.mint_usdc, &SPL_TOKEN_ID);
        let vault_ata = scout_ata(&rva, &self.mint_usdc, &SPL_TOKEN_ID);
        let (state_pda, mint_usdc) = (self.state_pda, self.mint_usdc);
        self.ctx
            .program(self.program_id)
            .call(instruction::CreateRedemptionRequest { amount })
            .accounts(accounts::CreateRedemptionRequest {
                state: state_pda,
                redemption_offer: ro,
                redemption_request: request,
                redeemer: user,
                redemption_vault_authority: rva,
                token_in_mint: mint_usdc,
                redeemer_token_account: redeemer_ata,
                vault_token_account: vault_ata,
                token_program: SPL_TOKEN_ID,
            })
            .signers(&[&user_kp])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Open a redemption request against the TRANSFER-FEE offer (Token-2022 `mint_fee` in).
    ///
    /// Permissionless, exactly like the generated action — the only difference is that token_in
    /// charges a transfer fee, so the vault receives strictly less than the `amount` the program
    /// records in `RedemptionRequest.amount` and adds to `requested_redemptions`.
    pub fn action_scout_create_request_fee(&mut self, amount: u64, sel: u8) -> bool {
        let ro = self.redemption_offer_fee_pda;
        let id = match self.request_counter_of(&ro) {
            Some(v) => v,
            None => return false,
        };
        let user_kp = self.pick_user(sel as u64);
        let user = user_kp.pubkey();
        let amount = if sel & 4 != 0 { amount } else { amount % (USER_USDC_START / 4) + 1 };
        let request = self.request_pda_of(&ro, id);
        let rva = self.redemption_vault_authority;
        let redeemer_ata = scout_ata(&user, &self.mint_fee, &SPL_TOKEN_2022_ID);
        let vault_ata = scout_ata(&rva, &self.mint_fee, &SPL_TOKEN_2022_ID);
        let (state_pda, mint_fee) = (self.state_pda, self.mint_fee);
        let ok = self
            .ctx
            .program(self.program_id)
            .call(instruction::CreateRedemptionRequest { amount })
            .accounts(accounts::CreateRedemptionRequest {
                state: state_pda,
                redemption_offer: ro,
                redemption_request: request,
                redeemer: user,
                redemption_vault_authority: rva,
                token_in_mint: mint_fee,
                redeemer_token_account: redeemer_ata,
                vault_token_account: vault_ata,
                token_program: SPL_TOKEN_2022_ID,
            })
            .signers(&[&user_kp])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        // Success-gated: a rejected request created no account, and registering one would make
        // P-0008 sum a claim the program never recorded — a false positive rather than a miss.
        if ok && self.scout_p8_next < SCOUT_REQ_CAP {
            self.scout_p8_reqs[self.scout_p8_next] = request;
            self.scout_p8_next += 1;
        } else if ok {
            // Ring full: mark it so the predicate bails out instead of summing a partial set.
            self.scout_p8_next = SCOUT_REQ_CAP + 1;
        }
        ok
    }

    /// Cancel a specific request under the TRANSFER-FEE offer, signed by its own redeemer.
    ///
    /// Cancellation is what turns the deposit shortfall into a loss: it transfers the recorded
    /// `amount` back out of a vault that only ever received `amount - fee`.
    pub fn action_scout_cancel_request_fee(&mut self, id: u64) -> bool {
        let ro = self.redemption_offer_fee_pda;
        let open = match self.open_requests_of(&ro) {
            Some(v) => v,
            None => return false,
        };
        let (rid, redeemer, _) = match open.iter().find(|(i, _, _)| *i == id) {
            Some(t) => *t,
            None => return false,
        };
        let kp = if redeemer == self.user_a.pubkey() {
            self.user_a.insecure_clone()
        } else {
            self.user_b.insecure_clone()
        };
        let request = self.request_pda_of(&ro, rid);
        let rva = self.redemption_vault_authority;
        let redeemer_ata = scout_ata(&redeemer, &self.mint_fee, &SPL_TOKEN_2022_ID);
        let vault_ata = scout_ata(&rva, &self.mint_fee, &SPL_TOKEN_2022_ID);
        let (state_pda, mint_fee, admin) =
            (self.state_pda, self.mint_fee, self.redemption_admin.pubkey());
        self.ctx
            .program(self.program_id)
            .call(instruction::CancelRedemptionRequest {})
            .accounts(accounts::CancelRedemptionRequest {
                state: state_pda,
                redemption_offer: ro,
                redemption_request: request,
                redeemer,
                signer: redeemer,
                redemption_admin: admin,
                redemption_vault_authority: rva,
                token_in_mint: mint_fee,
                redeemer_token_account: redeemer_ata,
                vault_token_account: vault_ata,
                token_program: SPL_TOKEN_2022_ID,
            })
            .signers(&[&kp])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Take the `usdc -> fee` offer. This is the POSITIVE CONTROL for P-0008: the program refuses
    /// it at `token_utils.rs:378` because `token_out` is fee-bearing. A run in which this returns
    /// `true` means the fixture's mint stopped being fee-bearing, not that the guard was removed.
    pub fn action_scout_take_fee_offer(&mut self, amount: u64) -> bool {
        let user_kp = self.user_a.insecure_clone();
        let user = user_kp.pubkey();
        let ova = self.offer_vault_authority;
        let (state_pda, offer, mint_usdc, mint_fee, boss) = (
            self.state_pda,
            self.offer_fee_pda,
            self.mint_usdc,
            self.mint_fee,
            self.boss.pubkey(),
        );
        self.ctx
            .program(self.program_id)
            .call(instruction::TakeOffer { token_in_amount: amount, approval_message: None })
            .accounts(accounts::TakeOffer {
                state: state_pda,
                offer,
                vault_authority: ova,
                mint_authority: self.mint_authority_pda,
                token_in_mint: mint_usdc,
                token_in_program: SPL_TOKEN_ID,
                vault_token_in_account: scout_ata(&ova, &mint_usdc, &SPL_TOKEN_ID),
                user_token_in_account: scout_ata(&user, &mint_usdc, &SPL_TOKEN_ID),
                boss_token_in_account: scout_ata(&boss, &mint_usdc, &SPL_TOKEN_ID),
                token_out_mint: mint_fee,
                token_out_program: SPL_TOKEN_2022_ID,
                vault_token_out_account: scout_ata(&ova, &mint_fee, &SPL_TOKEN_2022_ID),
                user_token_out_account: scout_ata(&user, &mint_fee, &SPL_TOKEN_2022_ID),
                user,
                boss,
            })
            .signers(&[&user_kp])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Raw SPL/Token-2022 balance at `addr` (offset 64 is `amount` in both layouts; the Token-2022
    /// extensions live after the 165-byte base, so the base offsets are shared).
    pub fn tok_amt(&self, addr: &Pubkey) -> u64 {
        self.ctx
            .account_data(addr)
            .ok()
            .filter(|d| d.len() >= SCOUT_TOKEN_MIN_LEN)
            .and_then(|d| {
                d[SCOUT_TOKEN_AMOUNT_OFFSET..SCOUT_TOKEN_MIN_LEN]
                    .try_into()
                    .ok()
                    .map(u64::from_le_bytes)
            })
            .unwrap_or(0)
    }

    /// The single pooled redemption vault token account for the transfer-fee mint.
    pub fn redemption_vault_fee(&self) -> Pubkey {
        scout_ata(&self.redemption_vault_authority, &self.mint_fee, &SPL_TOKEN_2022_ID)
    }

    /// Sum of `amount` over the open requests of the transfer-fee redemption offer — what the
    /// program believes it owes out of `redemption_vault_fee()`.
    pub fn claimed_fee(&self) -> u64 {
        self.open_requests_of(&self.redemption_offer_fee_pda)
            .map(|v| v.iter().map(|(_, _, a)| *a).sum())
            .unwrap_or(0)
    }

    /// Fulfil the oldest open request on the REVERSE offer, MINTING ONyc to the redeemer.
    ///
    /// token_in is usdc (program does not control it -> transferred from the vault to the boss);
    /// token_out is ONyc (program DOES control it -> `mint_tokens`, with the cap argument
    /// hard-coded to 0 at fulfill_redemption_request.rs:274).
    pub fn action_scout_fulfill_rev(&mut self) -> bool {
        let ro = self.redemption_offer_rev_pda;
        let open = match self.open_requests_of(&ro) {
            Some(v) => v,
            None => return false,
        };
        let (id, redeemer, _) = match open.first() {
            Some(t) => *t,
            None => return false,
        };
        let admin = self.redemption_admin.insecure_clone();
        let request = self.request_pda_of(&ro, id);
        let rva = self.redemption_vault_authority;
        let (state_pda, boss_pk) = (self.state_pda, self.boss.pubkey());
        let (offer_rev, ma) = (self.offer_rev_pda, self.mint_authority_pda);
        let (mint_usdc, mint_onyc) = (self.mint_usdc, self.mint_onyc);
        let vault_in = scout_ata(&rva, &mint_usdc, &SPL_TOKEN_ID);
        let vault_out = scout_ata(&rva, &mint_onyc, &SPL_TOKEN_ID);
        let user_out = scout_ata(&redeemer, &mint_onyc, &SPL_TOKEN_ID);
        let boss_in = scout_ata(&boss_pk, &mint_usdc, &SPL_TOKEN_ID);
        self.ctx
            .program(self.program_id)
            .call(instruction::FulfillRedemptionRequest {})
            .accounts(accounts::FulfillRedemptionRequest {
                state: state_pda,
                boss: boss_pk,
                offer: offer_rev,
                redemption_offer: ro,
                redemption_request: request,
                redemption_vault_authority: rva,
                vault_token_in_account: vault_in,
                vault_token_out_account: vault_out,
                token_in_mint: mint_usdc,
                token_in_program: SPL_TOKEN_ID,
                token_out_mint: mint_onyc,
                token_out_program: SPL_TOKEN_ID,
                user_token_out_account: user_out,
                boss_token_in_account: boss_in,
                mint_authority: ma,
                redeemer,
                redemption_admin: admin.pubkey(),
            })
            .signers(&[&admin])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Re-create `State` after `close_state` deallocated it.
    ///
    /// `close_state` is destructive by design and is NOT admin-gated by the generator, so it sits
    /// in the ordinary action pool. Without a way back, every action after it in the chain fails
    /// for want of a world rather than for any reason of its own. Exposing recovery as an action
    /// lets the fuzzer climb out on its own; doing it in close_state's hook is not possible, as a
    /// hook region may contain only pure assignments.
    ///
    /// A no-op (and reports failure) when `State` already exists, so it cannot silently reset a
    /// live world mid-chain.
    pub fn action_scout_rebuild_state(&mut self) -> bool {
        if self.state_exists() {
            return false;
        }
        self.rebuild_state();
        true
    }

    /// Drive `add_approver` / `remove_approver` across the whole key space, not just the one
    /// approver setup installed.
    ///
    /// The IDL arg is a bare `Pubkey`, so the generator cannot invent values for it and the static
    /// binding pins it to a single key — which leaves four branches structurally unreachable:
    /// `InvalidApprover` (both instructions reject `Pubkey::default()`), the approver2 slot, and
    /// `BothApproversFilled`. Selecting the key from a fuzzer byte reaches all of them.
    pub fn action_scout_approver_ops(&mut self, sel: u8, remove: bool) -> bool {
        let approver = match sel % 4 {
            0 => Pubkey::default(),      // -> InvalidApprover on both instructions
            1 => self.approver.pubkey(), // the one setup installed
            2 => self.user_a.pubkey(),   // fills approver2, then -> BothApproversFilled
            _ => self.user_b.pubkey(),
        };
        let boss = self.boss.insecure_clone();
        let outcome = if remove {
            self.ctx
                .program(self.program_id)
                .call(instruction::RemoveApprover { approver })
                .accounts(accounts::RemoveApprover { state: self.state_pda, boss: boss.pubkey() })
                .signers(&[&boss])
                .send()
        } else {
            self.ctx
                .program(self.program_id)
                .call(instruction::AddApprover { approver })
                .accounts(accounts::AddApprover { state: self.state_pda, boss: boss.pubkey() })
                .signers(&[&boss])
                .send()
        };
        outcome.map(|o| o.is_success()).unwrap_or(false)
    }

    /// Call `set_kill_switch` as someone other than the boss.
    ///
    /// The generated action always signs as `boss`, so `boss_signed` is always true and the
    /// `require!(boss_signed || admin_signed, UnauthorizedToEnable)` branch can never fail. An
    /// admin can ENABLE but only the boss can DISABLE, which is the asymmetry worth exercising —
    /// and it needs a signer who is an admin, and one who is neither.
    pub fn action_scout_kill_switch_as(&mut self, sel: u8, enable: bool) -> bool {
        let signer = match sel % 3 {
            0 => self.boss.insecure_clone(),
            1 => self.user_a.insecure_clone(),           // admin iff add_admin ran first
            _ => self.redemption_admin.insecure_clone(), // never an admin
        };
        self.ctx
            .program(self.program_id)
            .call(instruction::SetKillSwitch { enable })
            .accounts(accounts::SetKillSwitch { state: self.state_pda, signer: signer.pubkey() })
            .signers(&[&signer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// `propose_boss` with a fuzzer-chosen nominee, including `Pubkey::default()`.
    ///
    /// The static binding nominates the incumbent (deliberately — see SCOUT:BINDINGS), which never
    /// reaches `InvalidBossAddress`. This does, without ever handing authority to a key the harness
    /// cannot sign with.
    pub fn action_scout_propose_boss(&mut self, sel: u8) -> bool {
        let new_boss = if sel % 2 == 0 { Pubkey::default() } else { self.boss.pubkey() };
        let boss = self.boss.insecure_clone();
        self.ctx
            .program(self.program_id)
            .call(instruction::ProposeBoss { new_boss })
            .accounts(accounts::ProposeBoss { state: self.state_pda, boss: boss.pubkey() })
            .signers(&[&boss])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Take the approval-gated offer (`mint_appr -> onyc`, `needs_approval = true`).
    ///
    /// This has to be a COMPOUND action. `verify_approval_message_generic` loads the instruction
    /// at `current_index - 1` off the Instructions sysvar and demands it be an Ed25519 program
    /// instruction carrying the same message, so a single-instruction `.send()` can never satisfy
    /// it — the generated `action_take_offer` reaches `ApprovalRequired` and stops. Here the
    /// Ed25519 instruction and the take are pushed into ONE transaction.
    ///
    /// `expiry_delta` and `sel` are fuzzer-controlled so both sides of every approval guard are
    /// reachable: an expired message, a message bound to the wrong user, and the valid case.
    pub fn action_take_offer_with_approval(
        &mut self,
        token_in_amount: u64,
        expiry_delta: i32,
        sel: u8,
    ) -> bool {
        let user_kp = self.pick_user(sel as u64);
        let user = user_kp.pubkey();
        let now = scout_now(&self.ctx);

        // A raw u64 from the fuzzer exceeds the user's balance in ~every draw, so the transaction
        // would die at InsufficientFunds before `verify_offer_approval` is ever consulted — this
        // action would be dispatched forever and never once exercise the branch it exists for.
        // Bit 2 of `sel` keeps a quarter of the draws unclamped so the overflow / insufficient-funds
        // paths stay reachable too.
        let token_in_amount = if sel & 4 != 0 {
            token_in_amount
        } else {
            token_in_amount % (USER_USDC_START / 4) + 1
        };

        // The message the program will be handed. `expiry_delta` reaches back before `now`, which
        // is the only way to cover the `Expired` branch.
        let expiry_unix = (now as i64).saturating_add(expiry_delta as i64).max(0) as u64;
        // Half the draws bind the approval to the OTHER user, covering `WrongUser`.
        let bound_user = if sel & 2 == 0 { user } else { self.pick_user_pk((sel as u64) + 1) };

        let msg = onreapp::types::ApprovalMessage {
            program_id: self.program_id,
            user_pubkey: bound_user,
            expiry_unix,
        };
        let mut message_bytes = Vec::with_capacity(72);
        message_bytes.extend_from_slice(msg.program_id.as_ref());
        message_bytes.extend_from_slice(msg.user_pubkey.as_ref());
        message_bytes.extend_from_slice(&msg.expiry_unix.to_le_bytes());

        // A real Ed25519 signature by the registered approver. litesvm runs with sigverify off, so
        // the precompile itself is not re-verified here — signing for real keeps the harness
        // faithful in the direction that matters and means no property may claim anything about
        // forged signatures (see PROPERTIES.md / NOTES.md).
        let signature = self.approver.sign_message(&message_bytes);
        let ed25519_ix = scout_ed25519_instruction(&self.approver.pubkey(), &signature.into(), &message_bytes);

        self.ctx.pending_instructions.push(ed25519_ix);
        let queued = self
            .ctx
            .program(self.program_id)
            .call(instruction::TakeOffer {
                token_in_amount,
                approval_message: Some(msg),
            })
            .accounts(accounts::TakeOffer {
                offer: self.offer_appr_pda,
                state: self.state_pda,
                boss: self.boss.pubkey(),
                vault_authority: self.offer_vault_authority,
                vault_token_in_account: scout_ata(&self.offer_vault_authority, &self.mint_appr, &SPL_TOKEN_ID),
                vault_token_out_account: scout_ata(&self.offer_vault_authority, &self.mint_onyc, &SPL_TOKEN_ID),
                token_in_mint: self.mint_appr,
                token_in_program: SPL_TOKEN_ID,
                token_out_mint: self.mint_onyc,
                token_out_program: SPL_TOKEN_ID,
                user_token_in_account: scout_ata(&user, &self.mint_appr, &SPL_TOKEN_ID),
                user_token_out_account: scout_ata(&user, &self.mint_onyc, &SPL_TOKEN_ID),
                boss_token_in_account: scout_ata(&self.boss.pubkey(), &self.mint_appr, &SPL_TOKEN_ID),
                mint_authority: self.mint_authority_pda,
                user,
            })
            .signers(&[&user_kp])
            .add_transaction();
        if queued.is_err() {
            self.ctx.pending_instructions.clear();
            return false;
        }
        self.ctx
            .send_batch()
            .ok()
            .flatten()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
    // SCOUT:EXTRA-ACTIONS:END
}

#[invariant_test]
fn invariant_test(_f: &mut OnreappFixture) {
    scout_check_session!();
    // SCOUT:INVARIANTS:BEGIN
    // Every property is ARMED. Findings already reported to the client are silenced by id
    // through SCOUT_CHECK_MUTE in the bundle manifest, not by deleting the check — so each
    // mute can be lifted once its bug is fixed and the property becomes a regression guard.
    // Muting is announced on stderr ([SCOUT_CHECK_MUTED]); a silently disabled check would be
    // indistinguishable from a passing one.

    // SCOUT:INVARIANT:P-0002:BEGIN
    // Redemption vault coverage: the vault holds at least what open requests locked in it.
    //
    // NET, not a mirror — nothing in the program checks this, anywhere. create/cancel/fulfil each
    // move the same `amount` in or out of that account and are individually consistent, but
    // `redemption_vault_withdraw` (redemption_withdraw.rs) moves a caller-chosen amount out of the
    // SAME account with no reference to `requested_redemptions`, to any `RedemptionRequest`, or to
    // any reserve at all. The vault authority PDA carries no per-offer discriminator
    // (`seeds::REDEMPTION_OFFER_VAULT_AUTHORITY` alone), so one token account per mint custodies
    // every redemption offer's deposits.
    //
    // Liveness is ground truth, not mirrored: the registry records only that a request was created,
    // and the walk below counts it only while its account still exists. Fulfil and cancel both
    // `close` that account, so there is no status field to misread and nothing that can desync.
    //
    // Direction — this can only be MORE permissive than the truth, never a false positive:
    //   * a wrapped ring bails out entirely rather than summing a partial set (an under-count would
    //     hide exactly the shortfall this exists to catch),
    //   * a request whose account cannot be read is skipped, and
    //   * `redemption_vault_deposit` only ever raises the left-hand side.
    // A fire therefore means the vault really was drawn below the claims against it, leaving those
    // requests neither fulfillable nor cancellable.
    fn invariant_p_0002(f: &mut OnreappFixture) {
        if f.scout_p2_next > SCOUT_REQ_CAP {
            return;
        }
        let mut locked: u64 = 0;
        let reqs = f.scout_p2_reqs;
        for pda in reqs {
            if pda == Pubkey::default() {
                continue;
            }
            let data = match f.ctx.account_data(&pda) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if data.len() < SCOUT_REQ_MIN_LEN {
                continue;
            }
            let buf: [u8; 8] = data[SCOUT_REQ_AMOUNT_OFFSET..SCOUT_REQ_MIN_LEN]
                .try_into()
                .unwrap_or_default();
            locked = locked.saturating_add(u64::from_le_bytes(buf));
        }
        if locked == 0 {
            return;
        }
        let vault = f.redemption_vault_onyc;
        let vault_data = match f.ctx.account_data(&vault) {
            Ok(d) => d,
            Err(_) => return,
        };
        if vault_data.len() < SCOUT_TOKEN_MIN_LEN {
            return;
        }
        let vbuf: [u8; 8] = vault_data[SCOUT_TOKEN_AMOUNT_OFFSET..SCOUT_TOKEN_MIN_LEN]
            .try_into()
            .unwrap_or_default();
        let held = u64::from_le_bytes(vbuf);
        scout_check!(
            "P-0002",
            "vault-covers-open-redemption-requests",
            held >= locked,
            "P-0002: redemption vault {} holds {} ONyc but open redemption requests have {} locked \
             in it (shortfall {}). Those requests can now be neither fulfilled nor cancelled - both \
             paths transfer out of this account.",
            vault,
            held,
            locked,
            locked.saturating_sub(held)
        );
    }
    scout_run_property!("P-0002", invariant_p_0002(fixture));
    // SCOUT:INVARIANT:P-0002:END

    // SCOUT:INVARIANT:P-0003:BEGIN
    // Aggregate equals sum of parts: `RedemptionOffer.requested_redemptions` against the requests
    // that actually exist. Spans every path that can retire a request, not only the two that do so
    // today — a path that closed one without decrementing, or decremented by an amount other than
    // the one it locked, shows up here and nowhere else.
    //
    // What is shadow and what is not: the AMOUNTS are read live from the request accounts, but
    // the MEMBERSHIP of the summed set is shadow state (`scout_p3_reqs` / `scout_p3_next`), fed by
    // a success-gated hook on `create_redemption_request`. Membership can therefore drift, and the
    // guards below exist so that every way it can drift LOSES an observation rather than
    // manufacturing one:
    //   * Wrap: the hook writes at `scout_p3_next % SCOUT_REQ_CAP`, so the first overwrite happens
    //     only once the counter exceeds CAP; `scout_p3_next > SCOUT_REQ_CAP` disables the check on
    //     every state in which a slot could have been clobbered.
    //   * Duplicates: earlier slots are rescanned read-only, so one address cannot be summed twice
    //     against an aggregate that counts it once.
    //   * Retirement is not shadowed at all — both `cancel` and `fulfil` close the request account,
    //     so account existence IS openness and a stale registry entry simply reads as absent.
    //
    // The comparison is done in u128 on BOTH sides. Summing u64 amounts into a u64 accumulator and
    // asserting the aggregate's high half is zero would be strictly stronger than the property:
    // SCOUT_REQ_CAP u64 addends can legitimately exceed u64::MAX, and that state would be reported
    // as a violation rather than compared.
    fn invariant_p_0003(f: &mut OnreappFixture) {
        if f.scout_p3_next > SCOUT_REQ_CAP {
            return;
        }
        let offer_data = match f.ctx.account_data(&f.redemption_offer_pda) {
            Ok(d) => d,
            Err(_) => return,
        };
        if offer_data.len() < SCOUT_RO_MIN_LEN {
            return;
        }
        let rbuf: [u8; 16] = match offer_data[SCOUT_RO_REQUESTED_OFFSET..SCOUT_RO_MIN_LEN].try_into()
        {
            Ok(b) => b,
            Err(_) => return,
        };
        let recorded = u128::from_le_bytes(rbuf);

        let mut summed: u128 = 0;
        let reqs = f.scout_p3_reqs;
        for idx in 0..SCOUT_REQ_CAP {
            let pda = reqs[idx];
            if pda == Pubkey::default() {
                continue;
            }
            // De-duplicate against earlier slots, read-only: summing one address twice against an
            // aggregate that counts it once would manufacture a violation.
            let mut dup = false;
            for j in 0..idx {
                if reqs[j] == pda {
                    dup = true;
                }
            }
            if dup {
                continue;
            }
            let data = match f.ctx.account_data(&pda) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if data.len() < SCOUT_REQ_MIN_LEN {
                continue;
            }
            // A CLOSED request is not an open claim. Anchor's close path stamps this sentinel over
            // the discriminator, and the data can outlive the close, so length alone does not mean
            // live — summing a retired request would over-count against the aggregate.
            if data[0..8] == SCOUT_CLOSED_ACCOUNT_DISCRIMINATOR {
                continue;
            }
            // Scope from ON-CHAIN data: only requests the program itself records as belonging to
            // THIS offer are part of its aggregate. A mis-registered address then under-counts.
            let offer_bytes: [u8; 32] =
                match data[SCOUT_REQ_OFFER_OFFSET..SCOUT_REQ_OFFER_END].try_into() {
                    Ok(b) => b,
                    Err(_) => continue,
                };
            if Pubkey::new_from_array(offer_bytes) != f.redemption_offer_pda {
                continue;
            }
            let buf: [u8; 8] = match data[SCOUT_REQ_AMOUNT_OFFSET..SCOUT_REQ_MIN_LEN].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            };
            summed = summed.saturating_add(u64::from_le_bytes(buf) as u128);
        }
        scout_check!(
            "P-0003",
            "requested-redemptions-equals-sum-of-open-requests",
            recorded == summed,
            "P-0003: redemption offer {} records requested_redemptions={} but the requests that \
             still exist and name it sum to {}.",
            f.redemption_offer_pda,
            recorded,
            summed
        );
    }
    scout_run_property!("P-0003", invariant_p_0003(fixture));
    // SCOUT:INVARIANT:P-0003:END

    // SCOUT:INVARIANT:P-0004:BEGIN
    // While a supply cap is configured, the capped mint's supply must not exceed it.
    //
    // NET over a check the program applies in some places and not others. `mint_tokens`
    // (token_utils.rs:225-245) enforces `supply + amount <= max_supply` only when it is HANDED a
    // non-zero cap, and its own doc says it "prevents unbounded inflation when max supply is
    // configured". Two of the three callers pass `state.max_supply` — take_offer.rs:296 and
    // mint_to. The third, fulfill_redemption_request.rs:274, passes a hard-coded `0` with the
    // comment "No max supply cap for redemptions". Asserting the bound inside mint_tokens would be
    // a mirror; asserting it over the mint's persisted supply after every instruction is the net,
    // and it is blind to which caller did the minting.
    //
    // Reads the capped mint from `state.onyc_mint` rather than a fixture field, so the property
    // follows the configured mint if `set_onyc_mint` ever repoints it.
    //
    // Direction — cannot produce a false positive:
    //   * a zero cap means "no cap configured" and is skipped, matching mint_tokens' own semantics;
    //   * `configure_max_supply` performs no floor check, so a cap BELOW the current supply is
    //     legal on chain and would make this true by construction — the harness's only cap-setting
    //     action (`action_scout_configure_max_supply`) therefore always floors the cap at the
    //     supply of the moment, so any later excess was necessarily minted, not declared;
    //   * burns only ever lower the left-hand side;
    //   * a missing/short state or mint account returns early rather than firing.
    fn invariant_p_0004(f: &mut OnreappFixture) {
        let state_data = match f.ctx.account_data(&f.state_pda) {
            Ok(d) => d,
            Err(_) => return,
        };
        if state_data.len() < SCOUT_STATE_MAX_SUPPLY_END {
            return;
        }
        let cap_buf: [u8; 8] = state_data
            [SCOUT_STATE_MAX_SUPPLY_OFFSET..SCOUT_STATE_MAX_SUPPLY_END]
            .try_into()
            .unwrap_or_default();
        let max_supply = u64::from_le_bytes(cap_buf);
        if max_supply == 0 {
            return; // 0 means "no cap", exactly as mint_tokens reads it
        }
        let mint_buf: [u8; 32] = state_data
            [SCOUT_STATE_ONYC_MINT_OFFSET..SCOUT_STATE_ONYC_MINT_END]
            .try_into()
            .unwrap_or_default();
        let onyc_mint = Pubkey::new_from_array(mint_buf);
        let mint_data = match f.ctx.account_data(&onyc_mint) {
            Ok(d) => d,
            Err(_) => return,
        };
        if mint_data.len() < SCOUT_MINT_SUPPLY_END {
            return;
        }
        let supply_buf: [u8; 8] = mint_data[SCOUT_MINT_SUPPLY_OFFSET..SCOUT_MINT_SUPPLY_END]
            .try_into()
            .unwrap_or_default();
        let supply = u64::from_le_bytes(supply_buf);
        scout_check!(
            "P-0004",
            "onyc-supply-within-configured-max-supply",
            supply <= max_supply,
            "P-0004: mint {} has supply {} but state.max_supply is {} (over by {}). The cap is \
             enforced by mint_to and take_offer, which pass state.max_supply to mint_tokens, but \
             fulfill_redemption_request passes a hard-coded 0.",
            onyc_mint,
            supply,
            max_supply,
            supply.saturating_sub(max_supply)
        );
    }
    scout_run_property!("P-0004", invariant_p_0004(fixture));
    // SCOUT:INVARIANT:P-0004:END

    // SCOUT:INVARIANT:P-0005:BEGIN
    // No offer may exchange a token for itself.
    //
    // NET over a validation the program never performs. `make_offer` (make_offer.rs) relates
    // token_in_mint and token_out_mint nowhere, and grepping the whole program finds no such check
    // in any instruction — so a self-referential offer is accepted, stored, and priced like any
    // other. It is not economically meaningful at ANY price: `process_offer_core` computes
    // `token_out = token_in_net * 10^(out_dec + 9) / (price * 10^in_dec)`, so with both legs the
    // same mint the taker receives `token_in_net * 1e9 / price` of the very token they paid. Below
    // 1.0 that mints value from nothing; above it, it destroys the taker's. Neither is a trade.
    //
    // Asserting "the taker did not profit" would be the mirror of a check that does not exist and
    // would need a shadow of every balance. This asserts the structural precondition instead: read
    // the two mint fields straight out of each Offer account and require them to differ.
    //
    // Direction: reads only persisted bytes of accounts the harness watched being created, with a
    // length guard; an unreadable or short account is skipped, and a wrapped registry bails out.
    // It cannot fire on an offer that does not exist, and equality of the two fields has no benign
    // reading.
    fn invariant_p_0005(f: &mut OnreappFixture) {
        if f.scout_p5_next > SCOUT_OFFER_CAP {
            return;
        }
        let offers = f.scout_p5_offers;
        for offer in offers {
            if offer == Pubkey::default() {
                continue;
            }
            let data = match f.ctx.account_data(&offer) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if data.len() < SCOUT_OFFER_OUT_MINT_END {
                continue;
            }
            let in_buf: [u8; 32] = data[SCOUT_OFFER_IN_MINT_OFFSET..SCOUT_OFFER_IN_MINT_END]
                .try_into()
                .unwrap_or_default();
            let out_buf: [u8; 32] = data[SCOUT_OFFER_IN_MINT_END..SCOUT_OFFER_OUT_MINT_END]
                .try_into()
                .unwrap_or_default();
            let token_in = Pubkey::new_from_array(in_buf);
            let token_out = Pubkey::new_from_array(out_buf);
            scout_check!(
                "P-0005",
                "offer-legs-are-distinct-mints",
                token_in != token_out,
                "P-0005: offer {} exchanges mint {} for itself. Its taker receives \
                 token_in_net * 1e9 / price of the same token they paid, so any price below 1.0 \
                 mints value from nothing and any price above 1.0 destroys the taker's.",
                offer,
                token_in
            );
        }
    }
    scout_run_property!("P-0005", invariant_p_0005(fixture));
    // SCOUT:INVARIANT:P-0005:END

    // SCOUT:INVARIANT:P-0006:BEGIN
    // Every live offer's fee stays within the documented 10% ceiling, however it was written.
    //
    // NET, and a textbook one: the program clamps this fee in FOUR places and gets three of them
    // right. `make_offer.rs:137`, `make_redemption_offer.rs:163` and
    // `update_redemption_offer_fee.rs:84` all bound against `MAX_ALLOWED_FEE_BPS` (1000 = 10%).
    // `update_offer_fee.rs:99` alone bounds against `MAX_BASIS_POINTS` (10000 = 100%) — a different
    // constant, on the one path that can rewrite the field after creation.
    //
    // Mirroring any one of those `require!`s could never fail. Asserting the bound over the
    // PERSISTED field, after every instruction and across every offer, is what catches the writer
    // that used the wrong constant. This is the "bound" row of the mirror-vs-net table: not "the
    // handler clamps the fee", but "the fee never exceeds MAX, however it was written".
    //
    // Direction: reads only persisted bytes of offers the harness watched being created, with a
    // length guard. A wrapped registry bails out, a zero address is skipped, an unreadable or short
    // account is skipped — every guard fails toward a miss, never a false positive. The comparison
    // is against the program's own constant, so it cannot be stricter than the protocol intends.
    fn invariant_p_0006(f: &mut OnreappFixture) {
        if f.scout_p5_next > SCOUT_OFFER_CAP {
            return;
        }
        let offers = f.scout_p5_offers;
        for offer in offers {
            if offer == Pubkey::default() {
                continue;
            }
            let data = match f.ctx.account_data(&offer) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if data.len() < SCOUT_OFFER_FEE_END {
                continue;
            }
            let buf: [u8; 2] = data[SCOUT_OFFER_FEE_OFFSET..SCOUT_OFFER_FEE_END]
                .try_into()
                .unwrap_or_default();
            let fee = u16::from_le_bytes(buf);
            scout_check!(
                "P-0006",
                "offer-fee-within-max-allowed-bps",
                fee <= SCOUT_MAX_ALLOWED_FEE_BPS,
                "P-0006: offer {} has fee_basis_points {} which exceeds MAX_ALLOWED_FEE_BPS ({}). \
                 make_offer, make_redemption_offer and update_redemption_offer_fee all enforce that \
                 ceiling; update_offer_fee bounds against MAX_BASIS_POINTS (10000) instead.",
                offer,
                fee,
                SCOUT_MAX_ALLOWED_FEE_BPS
            );
        }
    }
    scout_run_property!("P-0006", invariant_p_0006(fixture));
    // SCOUT:INVARIANT:P-0006:END

    // SCOUT:INVARIANT:P-0008:BEGIN
    // Solvency of the pooled redemption vault for the TRANSFER-FEE mint.
    //
    // Same statement as P-0002, deliberately, but over a vault the boss cannot reach:
    // `pick_vault_mint` returns only usdc or onyc, so no `redemption_vault_withdraw` in this
    // harness can touch `mint_fee`'s vault. Any violation here is therefore reachable through
    // PERMISSIONLESS actions alone — which is the entire point of the property, and the reason it
    // is worth carrying alongside a confirmed sibling rather than being folded into it.
    //
    // Why it is a net, not a mirror: no line of the program compares these two quantities. The
    // program records the amount a redeemer ASKED to lock (`RedemptionRequest.amount`, and the
    // same figure into `requested_redemptions`) while the vault receives whatever the token
    // program actually delivered. On a mint with a live `TransferFeeConfig` those differ, and
    // nothing on this path consults `has_transfer_fee` — it has exactly two call sites in the
    // whole program, both inside `execute_token_operations` (`token_utils.rs:374,378`), which
    // only the offer path reaches.
    //
    // False positives — every guard fails toward a MISS, never toward a fire:
    //   * The sum is scoped from ON-CHAIN data: each candidate's `RedemptionRequest.offer` must
    //     equal the transfer-fee redemption offer. The registry only PROPOSES addresses; the
    //     program's own record decides whether each is a claim against THIS vault. A wrongly
    //     registered request therefore under-counts instead of manufacturing a shortfall.
    //   * De-duplicated within the pass, so no address can be counted twice.
    //   * The registry is appended only on success, and both retirement paths (`cancel`,
    //     `fulfil`) close the request account, so account existence IS openness.
    //   * A wrapped ring bails out rather than summing a partial set.
    //   * An unreadable or short VAULT account returns rather than reading as zero — defaulting
    //     it would turn a layout mistake into a fabricated shortfall against a real claim.
    //   * `redemption_vault_deposit` can only raise the left-hand side.
    fn invariant_p_0008(f: &mut OnreappFixture) {
        if f.scout_p8_next > SCOUT_REQ_CAP {
            return;
        }
        let vault = f.redemption_vault_fee_ata;
        // An unreadable or short vault account is SKIPPED, not read as zero: defaulting it to 0
        // would turn a layout mistake into a fabricated shortfall against a real claim.
        let held = match f.ctx.account_data(&vault) {
            Ok(d) if d.len() >= SCOUT_TOKEN_MIN_LEN => {
                match d[SCOUT_TOKEN_AMOUNT_OFFSET..SCOUT_TOKEN_MIN_LEN].try_into() {
                    Ok(buf) => u64::from_le_bytes(buf),
                    Err(_) => return,
                }
            }
            _ => return,
        };

        let mut claimed: u64 = 0;
        let reqs = f.scout_p8_reqs;
        let want_offer = f.redemption_offer_fee_pda;
        for idx in 0..SCOUT_REQ_CAP {
            let pda = reqs[idx];
            if pda == Pubkey::default() {
                continue;
            }
            // De-duplicate within the pass: counting one request twice would inflate the claim.
            // Done by scanning EARLIER registry slots read-only (the predicate grammar allows
            // assigning only to plain locals, so no scratch array is available).
            let mut dup = false;
            for j in 0..idx {
                if reqs[j] == pda {
                    dup = true;
                }
            }
            if dup {
                continue;
            }
            let data = match f.ctx.account_data(&pda) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if data.len() < SCOUT_REQ_MIN_LEN {
                continue;
            }
            // A CLOSED request is not an open claim. Anchor's close path stamps this sentinel over
            // the discriminator, and the data can outlive the close, so length alone does not mean
            // live — summing a retired request would over-count against the aggregate.
            if data[0..8] == SCOUT_CLOSED_ACCOUNT_DISCRIMINATOR {
                continue;
            }
            // SCOPE THE SUM FROM ON-CHAIN DATA, not from the registry's say-so. Only requests the
            // program itself records as belonging to the transfer-fee offer are claims against
            // THIS vault; anything else would be a claim against the usdc or onyc vault and would
            // manufacture a shortfall here. A wrongly-registered request now under-counts (a
            // miss) instead of firing (a false positive).
            let offer_bytes: [u8; 32] =
                match data[SCOUT_REQ_OFFER_OFFSET..SCOUT_REQ_OFFER_END].try_into() {
                    Ok(b) => b,
                    Err(_) => continue,
                };
            if Pubkey::new_from_array(offer_bytes) != want_offer {
                continue;
            }
            let buf: [u8; 8] = match data[SCOUT_REQ_AMOUNT_OFFSET..SCOUT_REQ_MIN_LEN].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            };
            claimed = claimed.saturating_add(u64::from_le_bytes(buf));
        }
        scout_check!(
            "P-0008",
            "fee-mint-redemption-vault-covers-open-claims",
            held >= claimed,
            "P-0008: the redemption vault {} for the transfer-fee mint {} holds {} but open \
             redemption requests have {} locked against it (shortfall {}). token_in charges a \
             transfer fee, so each deposit arrived short of the amount the program recorded; \
             `has_transfer_fee` is consulted only on the offer path (token_utils.rs:374,378) and \
             nowhere on the redemption path. No privileged signer participates.",
            vault,
            f.mint_fee,
            held,
            claimed,
            claimed.saturating_sub(held)
        );
    }
    scout_run_property!("P-0008", invariant_p_0008(fixture));
    // SCOUT:INVARIANT:P-0008:END
    // SCOUT:INVARIANTS:END
}
