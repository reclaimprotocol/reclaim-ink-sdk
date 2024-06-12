pub mod tests {
    use crate::reclaim::*;
    use ink::{
        env::test::{default_accounts, DefaultAccounts},
        primitives::AccountId,
    };

    fn get_default_test_accounts() -> DefaultAccounts<ink::env::DefaultEnvironment> {
        default_accounts::<ink::env::DefaultEnvironment>()
    }

    fn set_caller(caller: AccountId) {
        ink::env::test::set_caller::<ink::env::DefaultEnvironment>(caller);
    }

    #[ink::test]
    fn init() {
        let accounts = get_default_test_accounts();
        let alice = accounts.alice;
        set_caller(alice);
        let reclaim = Reclaim::new();
        assert_eq!(reclaim.get_owner(), alice);
        assert_eq!(reclaim.get_current_epoch(), 0_u64);
    }

    #[ink::test]
    fn should_add_epochs() {
        let mut reclaim = Reclaim::new();

        let w1 = Witness {
            address: "0x244897572368eadf65bfbc5aec98d8e5443a9072".to_string(),
            host: "http".to_string(),
        };
        let mut witnesses_vec = Vec::<Witness>::new();
        witnesses_vec.push(w1);
        let minimum_witness = 1;
        assert_eq!(reclaim.add_epoch(witnesses_vec, minimum_witness), Ok(()));
    }

    #[ink::test]
    fn should_approve_valid_proofs() {
        let mut reclaim = Reclaim::new();

        let w1 = Witness {
            address: "0x244897572368eadf65bfbc5aec98d8e5443a9072".to_string(),
            host: "http".to_string(),
        };
        let mut witnesses_vec = Vec::<Witness>::new();
        witnesses_vec.push(w1);
        let minimum_witness = 1;
        assert_eq!(reclaim.add_epoch(witnesses_vec, minimum_witness), Ok(()));

        let claim_info = ClaimInfo {
            provider: "http".to_string(),
            parameters: "{\"body\":\"\",\"geoLocation\":\"in\",\"method\":\"GET\",\"responseMatches\":[{\"type\":\"regex\",\"value\":\"_steamid\\\">Steam ID: (?<CLAIM_DATA>.*)</div>\"}],\"responseRedactions\":[{\"jsonPath\":\"\",\"regex\":\"_steamid\\\">Steam ID: (?<CLAIM_DATA>.*)</div>\",\"xPath\":\"id(\\\"responsive_page_template_content\\\")/div[@class=\\\"page_header_ctn\\\"]/div[@class=\\\"page_content\\\"]/div[@class=\\\"youraccount_steamid\\\"]\"}],\"url\":\"https://store.steampowered.com/account/\"}".to_string(),
            context: "{\"contextAddress\":\"user's address\",\"contextMessage\":\"for acmecorp.com on 1st january\",\"extractedParameters\":{\"CLAIM_DATA\":\"76561199601812329\"},\"providerHash\":\"0xffd5f761e0fb207368d9ebf9689f077352ab5d20ae0a2c23584c2cd90fc1b1bf\"}".to_string(),
        };

        let complete_claim_data = CompleteClaimData {
            identifier: "0xd1dcfc5338cb588396e44e6449e8c750bd4d76332c7e9440c92383382fced0fd"
                .to_string(),
            owner: "0x13239fc6bf3847dfedaf067968141ec0363ca42f".to_string(),
            epoch: 1_u64,
            timestampS: 1712174155_u64,
        };

        let mut sigs = Vec::<String>::new();

        let str_signature = "0x2888485f650f8ed02d18e32dd9a1512ca05feb83fc2cbf2df72fd8aa4246c5ee541fa53875c70eb64d3de9143446229a250c7a762202b7cc289ed31b74b31c811c".to_string();

        sigs.push(str_signature);

        let signed_claim = SignedClaim {
            claim: complete_claim_data,
            signatures: sigs,
        };

        dbg!(&signed_claim);
        assert_eq!(reclaim.verify_proof(claim_info, signed_claim), Ok(()));
    }
}
