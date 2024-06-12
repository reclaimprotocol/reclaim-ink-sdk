#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![allow(non_snake_case)]

pub use reclaim::ReclaimRef;

#[cfg(test)]
mod tests;

mod identity_digest;

#[ink::contract]
pub mod reclaim {
    use ecdsa::RecoveryId;
    use ink::prelude::string::String;
    use ink::prelude::string::ToString;
    use ink::prelude::vec::Vec;
    use ink::prelude::{format, vec};
    use ink::storage::Mapping;
    use k256::ecdsa::{Signature, VerifyingKey};
    use sha2::Sha256;
    use sha3::{Digest, Keccak256};

    use crate::identity_digest::Identity256;

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Witness {
        pub address: String,
        pub host: String,
    }

    impl Witness {
        pub fn get_addresses(witness: Vec<Witness>) -> Vec<String> {
            let mut vec_addresses = vec![];
            for wit in witness {
                vec_addresses.push(wit.address);
            }
            vec_addresses
        }
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Epoch {
        pub id: u64,
        pub timestamp_start: u64,
        pub timestamp_end: u64,
        pub minimum_witness_for_claim_creation: u128,
        pub witness: Vec<Witness>,
    }

    fn generate_random_seed(bytes: Vec<u8>, offset: usize) -> u32 {
        let hash_slice = &bytes[offset..offset + 4];
        let mut seed = 0u32;
        for (i, &byte) in hash_slice.iter().enumerate() {
            seed |= u32::from(byte) << (i * 8);
        }

        seed
    }

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ClaimInfo {
        pub provider: String,
        pub parameters: String,
        pub context: String,
    }

    impl ClaimInfo {
        pub fn hash(&self) -> String {
            let mut hasher = Keccak256::new();
            let hash_str = format!(
                "{}\n{}\n{}",
                &self.provider, &self.parameters, &self.context
            );
            hasher.update(&hash_str);

            let hash = hasher.finalize().to_vec();
            append_0x(hex::encode(hash).as_str())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct CompleteClaimData {
        pub identifier: String,
        pub owner: String,
        pub epoch: u64,
        pub timestampS: u64,
    }

    impl CompleteClaimData {
        pub fn serialise(&self) -> String {
            format!(
                "{}\n{}\n{}\n{}",
                &self.identifier,
                &self.owner.to_string(),
                &self.timestampS.to_string(),
                &self.epoch.to_string()
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedClaim {
        pub claim: CompleteClaimData,
        pub signatures: Vec<String>,
    }

    impl SignedClaim {
        pub fn recover_signers_of_signed_claim(self) -> Vec<String> {
            // use crate::claims::identity_digest::Identity256;
            use digest::Update;
            // Create empty array
            let mut expected = vec![];
            // Hash the signature
            let serialised_claim = self.claim.serialise();

            let bm = keccak256_eth(serialised_claim.as_str());
            let message_hash = bm.to_vec();

            // For each signature in the claim
            for mut complete_signature in self.signatures {
                complete_signature.remove(0);
                complete_signature.remove(0);
                let rec_param = complete_signature
                    .get((complete_signature.len() - 2)..(complete_signature.len()))
                    .unwrap();
                let mut mut_sig_str = complete_signature.clone();
                mut_sig_str.pop();
                mut_sig_str.pop();

                let rec_dec = hex::decode(rec_param).unwrap();
                let rec_norm = rec_dec.first().unwrap() - 27;
                let r_s = hex::decode(mut_sig_str).unwrap();

                let id = match rec_norm {
                    0 => RecoveryId::new(false, false),
                    1 => RecoveryId::new(true, false),
                    2_u8..=u8::MAX => todo!(),
                };

                let signature = Signature::from_bytes(r_s.as_slice().into()).unwrap();
                let message_digest = Identity256::new().chain(&message_hash);

                // Recover the public key
                let verkey =
                    VerifyingKey::recover_from_digest(message_digest, &signature, id).unwrap();
                let key: Vec<u8> = verkey.to_encoded_point(false).as_bytes().into();
                let hasher = Keccak256::new_with_prefix(&key[1..]);

                let hash = hasher.finalize().to_vec();

                let address_bytes = hash.get(12..).unwrap();
                let public_key = append_0x(&hex::encode(address_bytes));
                expected.push(public_key);
            }
            expected
        }

        pub fn fetch_witness_for_claim(
            epoch: Epoch,
            identifier: String,
            timestamp: u64,
        ) -> Vec<Witness> {
            let mut selected_witness = vec![];

            // Create a hash from identifier+epoch+minimum+timestamp
            let hash_str = format!(
                "{}\n{}\n{}\n{}",
                hex::encode(identifier),
                epoch.minimum_witness_for_claim_creation,
                timestamp,
                epoch.id
            );
            let result = hash_str.as_bytes().to_vec();
            let mut hasher = Sha256::new();
            hasher.update(result);
            let hash_result = hasher.finalize().to_vec();
            let witenesses_left_list = epoch.witness;
            let mut byte_offset = 0;
            let witness_left = witenesses_left_list.len();
            for _i in 0..epoch.minimum_witness_for_claim_creation {
                let random_seed = generate_random_seed(hash_result.clone(), byte_offset) as usize;
                let witness_index = random_seed % witness_left;
                let witness = witenesses_left_list.get(witness_index);
                if let Some(data) = witness {
                    selected_witness.push(data.clone())
                }
                byte_offset = (byte_offset + 4) % hash_result.len();
            }

            selected_witness
        }
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Proof {
        pub claimInfo: ClaimInfo,
        pub signedClaim: SignedClaim,
    }

    pub fn append_0x(content: &str) -> String {
        let mut initializer = String::from("0x");
        initializer.push_str(content);
        initializer
    }

    pub fn keccak256_eth(message: &str) -> Vec<u8> {
        let message: &[u8] = message.as_ref();

        let mut eth_message =
            format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
        eth_message.extend_from_slice(message);
        let mut hasher = Keccak256::new();
        hasher.update(&eth_message);

        hasher.finalize().to_vec()
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ReclaimError {
        OnlyOwner,
        AlreadyInitialized,
        HashMismatch,
        LengthMismatch,
        SignatureMismatch,
    }

    #[ink(event)]
    pub struct EpochAdded {
        epoch_id: u64,
    }

    #[ink(event)]
    pub struct ProofVerified {
        epoch_id: u64,
    }

    #[ink(event)]
    pub struct WitnessRetrieved {
        witness: Vec<String>,
    }

    #[ink(storage)]
    pub struct Reclaim {
        pub owner: AccountId,
        pub current_epoch: u64,
        pub epochs: Mapping<u64, Epoch>,
    }

    impl Default for Reclaim {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Reclaim {
        #[ink(constructor)]
        pub fn new() -> Self {
            let owner = Self::env().caller();
            let current_epoch = 0_u64;
            let epochs = Mapping::new();
            Self {
                owner,
                current_epoch,
                epochs,
            }
        }

        #[ink(message)]
        pub fn add_epoch(
            &mut self,
            witness: Vec<Witness>,
            minimum_witness: u128,
        ) -> Result<(), ReclaimError> {
            let caller = Self::env().caller();
            if self.owner != caller {
                return Err(ReclaimError::OnlyOwner);
            }
            let new_epoch_id = self.current_epoch + 1_u64;
            let now = ink::env::block_timestamp::<ink::env::DefaultEnvironment>();
            let epoch = Epoch {
                id: new_epoch_id,
                witness,
                timestamp_start: now,
                timestamp_end: now + 10000_u64,
                minimum_witness_for_claim_creation: minimum_witness,
            };
            self.epochs.insert(new_epoch_id, &epoch);
            self.current_epoch = new_epoch_id;
            Self::env().emit_event(EpochAdded {
                epoch_id: new_epoch_id,
            });
            Ok(())
        }

        #[ink(message)]
        pub fn verify_proof(
            &mut self,
            claim_info: ClaimInfo,
            signed_claim: SignedClaim,
        ) -> Result<(), ReclaimError> {
            let epoch_count = self.current_epoch;
            let current_epoch = self.epochs.get(epoch_count).unwrap();
            let hashed = claim_info.hash();
            if signed_claim.claim.identifier != hashed {
                return Err(ReclaimError::HashMismatch);
            }

            let expected_witness = crate::reclaim::SignedClaim::fetch_witness_for_claim(
                current_epoch.clone(),
                signed_claim.claim.identifier.clone(),
                signed_claim.claim.timestampS,
            );
            let expected_witness_addresses = Witness::get_addresses(expected_witness);

            let signed_witness = signed_claim.recover_signers_of_signed_claim();

            if expected_witness_addresses.len() != signed_witness.len() {
                return Err(ReclaimError::LengthMismatch);
            }

            Self::env().emit_event(WitnessRetrieved {
                witness: signed_witness.clone(),
            });
            for signed in signed_witness {
                if !expected_witness_addresses.contains(&signed) {
                    return Err(ReclaimError::SignatureMismatch);
                }
            }
            Self::env().emit_event(ProofVerified {
                epoch_id: current_epoch.id,
            });
            Ok(())
        }

        #[ink(message)]
        pub fn get_owner(&self) -> AccountId {
            self.owner
        }

        #[ink(message)]
        pub fn get_current_epoch(&self) -> u64 {
            self.current_epoch
        }
    }

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// A helper function used for calling contract messages.
        use ink_e2e::{account_id, build_message, AccountKeyring};

        /// The End-to-End test `Result` type.
        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        /// We test that we can read and write a value from the on-chain contract contract.
        #[ink_e2e::test]
        async fn it_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let reclaim = ReclaimRef::new();
            let contract_account_id = client
                .instantiate("reclaim_ink", &ink_e2e::bob(), reclaim, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            let w1 = Witness {
                address: "0x244897572368eadf65bfbc5aec98d8e5443a9072".to_string(),
                host: "http".to_string(),
            };
            let mut witnesses_vec = Vec::<Witness>::new();
            witnesses_vec.push(w1);
            let minimum_witness = 1;

            let add_ep = build_message::<ReclaimRef>(contract_account_id.clone())
                .call(|reclaim| reclaim.add_epoch(witnesses_vec.clone(), minimum_witness));
            let add_ep_result = client
                .call(&ink_e2e::bob(), add_ep, 0, None)
                .await
                .expect("Add Epoch Failed");
            assert!(matches!(add_ep_result.return_value(), Ok(())));

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

            let get = build_message::<ReclaimRef>(contract_account_id.clone())
                .call(|reclaim| reclaim.get_current_epoch());
            let get_result = client.call_dry_run(&ink_e2e::alice(), &get, 0, None).await;
            let ret_val = get_result.return_value();
            assert!(matches!(ret_val, 1));

            let verify = build_message::<ReclaimRef>(contract_account_id.clone())
                .call(|reclaim| reclaim.verify_proof(claim_info.clone(), signed_claim.clone()));
            let verify_result = client
                .call_dry_run(&ink_e2e::alice(), &verify, 0, None)
                .await;
            assert!(matches!(verify_result.return_value(), Ok(())));

            Ok(())
        }
    }
}
