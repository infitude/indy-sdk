using Hyperledger.Indy.AnonCredsApi;
using Hyperledger.Indy.CryptoApi;
using Hyperledger.Indy.DidApi;
using Hyperledger.Indy.LedgerApi;
using Hyperledger.Indy.PoolApi;
using Hyperledger.Indy.Samples.Utils;
using Hyperledger.Indy.WalletApi;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Hyperledger.Indy.Samples
{
    public class GettingStarted
    {

        public static async Task Execute()
        {

            //import time

            //from indy import anoncreds, crypto, did, ledger, pool, wallet

            //import json
            //import logging
            //from typing import Optional

            //from indy.error import ErrorCode, IndyError

            //from src.utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION

            //logger = logging.getLogger(__name__)
            //logging.basicConfig(level= logging.INFO)


            //async def run():
            //    logger.info("Getting started -> started")

            Console.WriteLine("Getting started -> started");

            //    pool_name = 'pool1'
            //    logger.info("Open Pool Ledger: {}".format(pool_name))
            //    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
            //    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

            //    # Set protocol version 2 to work with Indy Node 1.4
            //    await pool.set_protocol_version(PROTOCOL_VERSION)

            //    try:
            //        await pool.create_pool_ledger_config(pool_name, pool_config)
            //    except IndyError as ex:
            //        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            //            pass
            //    pool_handle = await pool.open_pool_ledger(pool_name, None)


            await PoolUtils.CreatePoolLedgerConfig();
            using (var pool = await Pool.OpenPoolLedgerAsync(PoolUtils.DEFAULT_POOL_NAME, "{}"))
            {
                Console.WriteLine("==============================");
                Console.WriteLine("=== Getting Trust Anchor credentials for Faber, Acme, Thrift and Government  ==");
                Console.WriteLine("------------------------------");

                Console.WriteLine("\"Sovrin Steward\" -> Create wallet");

                //    steward_wallet_config = json.dumps({"id": "sovrin_steward_wallet"})
                //    steward_wallet_credentials = json.dumps({"key": "steward_wallet_key"})
                //    try:
                //        await wallet.create_wallet(steward_wallet_config, steward_wallet_credentials)
                //    except IndyError as ex:
                //        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
                //            pass

                //    steward_wallet = await wallet.open_wallet(steward_wallet_config, steward_wallet_credentials)

                var stewardWalletConfig = "{\"id\":\"sovrin_steward_wallet\"}";
                var stewardWalletCredentials = "{\"key\":\"steward_wallet_key\"}";

                await WalletUtils.CreateWalletAsync(stewardWalletConfig, stewardWalletCredentials);

                var stewardWallet = await Wallet.OpenWalletAsync(stewardWalletConfig, stewardWalletCredentials);

                //    logger.info("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
                //    steward_did_info = {'seed': '000000000000000000000000Steward1'}
                //    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet, json.dumps(steward_did_info))

                Console.WriteLine("\"Sovrin Steward\" -> Create and store in Wallet DID from seed");
                var stewardDidInfo = "{\"seed\":\"000000000000000000000000Steward1\"}";
                var stewardDidResult = await Did.CreateAndStoreMyDidAsync(stewardWallet, stewardDidInfo);
                var stewardDid = stewardDidResult.Did;
                var stewardVerKey = stewardDidResult.VerKey;

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Government Onboarding  ==");
                Console.WriteLine("------------------------------");

                //    government_wallet_config = json.dumps({"id": "government_wallet"})
                //    government_wallet_credentials = json.dumps({"key": "government_wallet_key"})
                //    government_wallet, steward_government_key, government_steward_did, government_steward_key, _ \
                //        = await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Government", None,
                //                           government_wallet_config, government_wallet_credentials)

                var governmentWalletConfig = "{\"id\":\"government_wallet\"}";
                var governmentWalletCredentials = "{\"key\":\"government_wallet_key\"}";
                OnboardingResult governmentOnboarding = await Onboarding(pool, "Sovrin Steward", stewardWallet, stewardDid, "Government", null,
                                           governmentWalletConfig, governmentWalletCredentials);

                var governmentWallet = governmentOnboarding.toWallet;

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Government getting Verinym  ==");
                Console.WriteLine("------------------------------");

                //    government_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did,
                //                                       steward_government_key, "Government", government_wallet, government_steward_did,
                //                                       government_steward_key, 'TRUST_ANCHOR')

                var governmentDid = await GetVerinym(pool, "Sovrin Steward", stewardWallet, stewardDid,
                                                                governmentOnboarding.fromToVarKey, "Government",
                                                                governmentOnboarding.toWallet,
                                                                governmentOnboarding.toFromDid,
                                                                governmentOnboarding.toFromVarKey, "TRUST_ANCHOR");

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Faber Onboarding  ==");
                Console.WriteLine("------------------------------");

                //    faber_wallet_config = json.dumps({"id": "faber_wallet"})
                //    faber_wallet_credentials = json.dumps({"key": "faber_wallet_key"})
                //    faber_wallet, steward_faber_key, faber_steward_did, faber_steward_key, _ = \
                //        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Faber", None, faber_wallet_config,
                //                         faber_wallet_credentials)

                var faberWalletConfig = "{\"id\":\"faber_wallet\"}";
                var faberWalletCredentials = "{\"key\":\"faber_wallet_key\"}";
                OnboardingResult faberOnboarding = await Onboarding(pool, "Sovrin Steward", stewardWallet, stewardDid, "Faber", null,
                                           faberWalletConfig, faberWalletCredentials);

                var faberWallet = faberOnboarding.toWallet;

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Faber getting Verinym  ==");
                Console.WriteLine("------------------------------");

                //    faber_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_faber_key,
                //                                  "Faber", faber_wallet, faber_steward_did, faber_steward_key, 'TRUST_ANCHOR')

                var faberDid = await GetVerinym(pool, "Sovrin Steward", stewardWallet, stewardDid,
                                                faberOnboarding.fromToVarKey, "Faber",
                                                faberOnboarding.toWallet,
                                                faberOnboarding.toFromDid,
                                                faberOnboarding.toFromVarKey, "TRUST_ANCHOR");

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Acme Onboarding  ==");
                Console.WriteLine("------------------------------");

                //    acme_wallet_config = json.dumps({"id": "acme_wallet"})
                //    acme_wallet_credentials = json.dumps({"key": "acme_wallet_key"})
                //    acme_wallet, steward_acme_key, acme_steward_did, acme_steward_key, _ = \
                //        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Acme", None, acme_wallet_config,
                //                         acme_wallet_credentials)

                var acmeWalletConfig = "{\"id\":\"acme_wallet\"}";
                var acmeWalletCredentials = "{\"key\":\"acme_wallet_key\"}";
                OnboardingResult acmeOnboarding = await Onboarding(pool, "Sovrin Steward", stewardWallet, stewardDid, "Acme", null,
                                           acmeWalletConfig, acmeWalletCredentials);

                var acmeWallet = acmeOnboarding.toWallet;

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Acme getting Verinym  ==");
                Console.WriteLine("------------------------------");

                //    acme_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_acme_key,
                //                                 "Acme", acme_wallet, acme_steward_did, acme_steward_key, 'TRUST_ANCHOR')

                var acmeDid = await GetVerinym(pool, "Sovrin Steward", stewardWallet, stewardDid,
                                                acmeOnboarding.fromToVarKey, "Acme",
                                                acmeOnboarding.toWallet,
                                                acmeOnboarding.toFromDid,
                                                acmeOnboarding.toFromVarKey, "TRUST_ANCHOR");

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Thrift Onboarding  ==");
                Console.WriteLine("------------------------------");

                //    thrift_wallet_config = json.dumps({"id": " thrift_wallet"})
                //    thrift_wallet_credentials = json.dumps({"key": "thrift_wallet_key"})
                //    thrift_wallet, steward_thrift_key, thrift_steward_did, thrift_steward_key, _ = \
                //        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Thrift", None,
                //                         thrift_wallet_config, thrift_wallet_credentials)

                var thriftWalletConfig = "{\"id\":\"thrift_wallet\"}";
                var thriftWalletCredentials = "{\"key\":\"thrift_wallet_key\"}";
                OnboardingResult thriftOnboarding = await Onboarding(pool, "Sovrin Steward", stewardWallet, stewardDid, "Thrift", null,
                                           thriftWalletConfig, thriftWalletCredentials);

                var thriftWallet = thriftOnboarding.toWallet;

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Trust Anchor credentials - Thrift getting Verinym  ==");
                Console.WriteLine("------------------------------");

                //    thrift_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_thrift_key,
                //                                   "Thrift", thrift_wallet, thrift_steward_did, thrift_steward_key, 'TRUST_ANCHOR')

                var thriftDid = await GetVerinym(pool, "Sovrin Steward", stewardWallet, stewardDid,
                                                thriftOnboarding.fromToVarKey, "Thrift",
                                                thriftOnboarding.toWallet,
                                                thriftOnboarding.toFromDid,
                                                thriftOnboarding.toFromVarKey, "TRUST_ANCHOR");

                Console.WriteLine("==============================");
                Console.WriteLine("=== Credential Schemas Setup ==");
                Console.WriteLine("------------------------------");

                Console.WriteLine("\"Government\" -> Create \"Job-Certificate\" Schema");
                //    (job_certificate_schema_id, job_certificate_schema) = \
                //        await anoncreds.issuer_create_schema(government_did, 'Job-Certificate', '0.2',
                //                                             json.dumps(['first_name', 'last_name', 'salary', 'employee_status',
                //                                                         'experience']))

                var jobCertAttributes = JsonConvert.SerializeObject(new string[] { "first_name", "last_name", "salary", "employee_status", "experience" });
                IssuerCreateSchemaResult jobCertCreateSchemaResult = await AnonCreds.IssuerCreateSchemaAsync(governmentDid, "Job-Certificate", "0.2", jobCertAttributes);
                var jobCertificateSchemaId = jobCertCreateSchemaResult.SchemaId;
                var jobCertificateSchema = jobCertCreateSchemaResult.SchemaJson;

                Console.WriteLine("\"Government\" -> Send \"Job-Certificate\" Schema to Ledger");
                //    await send_schema(pool_handle, government_wallet, government_did, job_certificate_schema)

                await SendSchema(pool, governmentWallet, governmentDid, jobCertificateSchema);

                Console.WriteLine("\"Government\" -> Create \"Transcript\" Schema");
                //    (transcript_schema_id, transcript_schema) = \
                //        await anoncreds.issuer_create_schema(government_did, 'Transcript', '1.2',
                //                                             json.dumps(['first_name', 'last_name', 'degree', 'status',
                //                                                         'year', 'average', 'ssn']))

                var transcriptAttributes = JsonConvert.SerializeObject(new string[] { "first_name", "last_name", "degree", "status", "year", "average", "ssn" });
                IssuerCreateSchemaResult transcriptIssuerCreateSchemaResult = await AnonCreds.IssuerCreateSchemaAsync(governmentDid, "Transcript", "1.2", transcriptAttributes);
                var transcriptSchemaId = transcriptIssuerCreateSchemaResult.SchemaId;
                var transcriptSchema = transcriptIssuerCreateSchemaResult.SchemaJson;

                Console.WriteLine("\"Government\" -> Send \"Transcript\" Schema to Ledger");
                //    await send_schema(pool_handle, government_wallet, government_did, transcript_schema)

                await SendSchema(pool, governmentWallet, governmentDid, transcriptIssuerCreateSchemaResult.SchemaJson);

                //    time.sleep(1)  # sleep 1 second before getting schema
                System.Threading.Thread.Sleep(1000);

                Console.WriteLine("==============================");
                Console.WriteLine("=== Faber Credential Definition Setup ==");
                Console.WriteLine("------------------------------");

                Console.WriteLine("\"Faber\" -> Get \"Transcript\" Schema from Ledger");
                //    (_, transcript_schema) = await get_schema(pool_handle, faber_did, transcript_schema_id)

                var faberTranscriptSchemaResult = await GetSchema(pool, faberDid, transcriptSchemaId);
                var faberTranscriptSchema = faberTranscriptSchemaResult.ObjectJson;

                Console.WriteLine("\"Faber\" -> Create and store in Wallet \"Faber Transcript\" Credential Definition");
                //    (faber_transcript_cred_def_id, faber_transcript_cred_def_json) = \
                //        await anoncreds.issuer_create_and_store_credential_def(faber_wallet, faber_did, transcript_schema,
                //                                                               'TAG1', 'CL', '{"support_revocation": false}')

                IssuerCreateAndStoreCredentialDefResult faberICASCDR = await AnonCreds.IssuerCreateAndStoreCredentialDefAsync(faberWallet, faberDid, faberTranscriptSchema, "TAG1", "CL", "{\"support-revocaion\": false}");
                var faberTranscriptCredDefId = faberICASCDR.CredDefId;

                Console.WriteLine("\"Faber\" -> Send  \"Faber Transcript\" Credential Definition to Ledger");
                //    await send_cred_def(pool_handle, faber_wallet, faber_did, faber_transcript_cred_def_json)

                await SendCredDef(pool, faberWallet, faberDid, faberICASCDR.CredDefJson);

                Console.WriteLine("==============================");
                Console.WriteLine("=== Acme Credential Definition Setup ==");
                Console.WriteLine("------------------------------");

                Console.WriteLine("\"Acme\" -> Get from Ledger \"Job-Certificate\" Schema");
                //    (_, job_certificate_schema) = await get_schema(pool_handle, acme_did, job_certificate_schema_id)

                var acmeJobCertSchemaResult = await GetSchema(pool, acmeDid, jobCertificateSchemaId);
                var acmeJobCertSchema = acmeJobCertSchemaResult.ObjectJson;

                Console.WriteLine("\"Acme\" -> Create and store in Wallet \"Acme Job-Certificate\" Credential Definition");
                //    (acme_job_certificate_cred_def_id, acme_job_certificate_cred_def_json) = \
                //        await anoncreds.issuer_create_and_store_credential_def(acme_wallet, acme_did, job_certificate_schema,
                //                                                               'TAG1', 'CL', '{"support_revocation": false}')
                IssuerCreateAndStoreCredentialDefResult acmeICASCDR = await AnonCreds.IssuerCreateAndStoreCredentialDefAsync(acmeWallet, acmeDid, acmeJobCertSchema, "TAG1", "CL", "{\"support-revocaion\": false}");

                Console.WriteLine("\"Acme\" -> Send \"Acme Job-Certificate\" Credential Definition to Ledger");
                //    await send_cred_def(pool_handle, acme_wallet, acme_did, acme_job_certificate_cred_def_json)

                await SendCredDef(pool, acmeWallet, acmeDid, acmeICASCDR.CredDefJson);

                Console.WriteLine("==============================");
                Console.WriteLine("=== Getting Transcript with Faber ==");
                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Transcript with Faber - Onboarding ==");
                Console.WriteLine("------------------------------");

                //    alice_wallet_config = json.dumps({"id": " alice_wallet"})
                //    alice_wallet_credentials = json.dumps({"key": "alice_wallet_key"})
                //    alice_wallet, faber_alice_key, alice_faber_did, alice_faber_key, faber_alice_connection_response \
                //        = await onboarding(pool_handle, "Faber", faber_wallet, faber_did, "Alice", None, alice_wallet_config,
                //                           alice_wallet_credentials)

                var aliceWalletConfig = "{\"id\":\"alice_wallet\"}";
                var aliceWalletCredentials = "{\"key\":\"alice_wallet_key\"}";

                OnboardingResult aliceOnboarding = await Onboarding(pool, "Faber", faberWallet, faberDid, "Alice", null,
                           aliceWalletConfig, aliceWalletCredentials);

                var aliceWallet = aliceOnboarding.toWallet;
                var aliceFaberDid = aliceOnboarding.toFromDid;
                var faberAliceKey = aliceOnboarding.fromToVarKey;
                var faberAliceConnectionResponse = (JObject)JsonConvert.DeserializeObject(aliceOnboarding.decryptedConnectionJson);

                Console.WriteLine("==============================");
                Console.WriteLine("== Getting Transcript with Faber - Getting Transcript Credential ==");
                Console.WriteLine("------------------------------");

                Console.WriteLine("\"Faber\" -> Create \"Transcript\" Credential Offer for Alice");
                //    transcript_cred_offer_json = \
                //        await anoncreds.issuer_create_credential_offer(faber_wallet, faber_transcript_cred_def_id)
                var transcriptCredOfferJson = await AnonCreds.IssuerCreateCredentialOfferAsync(faberWallet, faberTranscriptCredDefId);

                Console.WriteLine("\"Faber\" -> Get key for Alice did");
                //    alice_faber_verkey = await did.key_for_did(pool_handle, acme_wallet, faber_alice_connection_response['did'])

                var aliceFaberVerkey = await Did.KeyForDidAsync(pool, acmeWallet, (string)faberAliceConnectionResponse.GetValue("did"));

                Console.WriteLine("\"Faber\" -> Authcrypt \"Transcript\" Credential Offer for Alice");
                //    authcrypted_transcript_cred_offer = await crypto.auth_crypt(faber_wallet, faber_alice_key, alice_faber_verkey,
                //                                                                transcript_cred_offer_json.encode('utf-8'))

                var authcryptedTranscriptCredOffer = await Crypto.AuthCryptAsync(faberWallet, faberAliceKey, aliceFaberVerkey, Encoding.UTF8.GetBytes(transcriptCredOfferJson));

                Console.WriteLine("\"Faber\" -> Send authcrypted \"Transcript\" Credential Offer to Alice");

                Console.WriteLine("\"Alice\" -> Authdecrypted \"Transcript\" Credential Offer from Faber");
                //    faber_alice_verkey, authdecrypted_transcript_cred_offer_json, authdecrypted_transcript_cred_offer = \
                //        await auth_decrypt(alice_wallet, alice_faber_key, authcrypted_transcript_cred_offer)

                AuthDecryptResult authDecryptedTranscriptOfferFaber = await AuthDecrypt(aliceWallet, aliceFaberVerkey, authcryptedTranscriptCredOffer);

                Console.WriteLine("\"Alice\" -> Create and store \"Alice\" Master Secret in Wallet");
                //    alice_master_secret_id = await anoncreds.prover_create_master_secret(alice_wallet, None)

                var aliceMasterSecretId = await AnonCreds.ProverCreateMasterSecretAsync(aliceWallet, null);

                Console.WriteLine("\"Alice\" -> Get \"Faber Transcript\" Credential Definition from Ledger");
                //    (faber_transcript_cred_def_id, faber_transcript_cred_def) = \
                //        await get_cred_def(pool_handle, alice_faber_did, authdecrypted_transcript_cred_offer['cred_def_id'])
                ParseResponseResult faberTranscriptCredDefResult = await GetCredDef(pool, aliceFaberDid, (string)authDecryptedTranscriptOfferFaber.authcryptedDidInfo["cred_def_id"]);

                Console.WriteLine("\"Alice\" -> Create \"Transcript\" Credential Request for Faber");
                //    (transcript_cred_request_json, transcript_cred_request_metadata_json) = \
                //        await anoncreds.prover_create_credential_req(alice_wallet, alice_faber_did,
                //                                                     authdecrypted_transcript_cred_offer_json,
                //                                                     faber_transcript_cred_def, alice_master_secret_id)

                ProverCreateCredentialRequestResult pccrr = await AnonCreds.ProverCreateCredentialReqAsync(aliceWallet, aliceFaberDid,
                                                                            authDecryptedTranscriptOfferFaber.authdecryptedDidInfoJson,
                                                                            faberTranscriptCredDefResult.ObjectJson, aliceMasterSecretId);

                Console.WriteLine("\"Alice\" -> Authcrypt \"Transcript\" Credential Request for Faber");
                //    authcrypted_transcript_cred_request = await crypto.auth_crypt(alice_wallet, alice_faber_key, faber_alice_verkey,
                //                                                                  transcript_cred_request_json.encode('utf-8'))

                var authcryptedTranscriptCredRequest = await Crypto.AuthCryptAsync(aliceWallet, aliceFaberVerkey, faberAliceKey, Encoding.UTF8.GetBytes(pccrr.CredentialRequestJson));

                Console.WriteLine("\"Alice\" -> Send authcrypted \"Transcript\" Credential Request to Faber");

                Console.WriteLine("\"Faber\" -> Authdecrypt \"Transcript\" Credential Request from Alice");
                //    alice_faber_verkey, authdecrypted_transcript_cred_request_json, _ = \
                //        await auth_decrypt(faber_wallet, faber_alice_key, authcrypted_transcript_cred_request)

                AuthDecryptResult faberTranscriptCredReqAlice = await AuthDecrypt(faberWallet, faberAliceKey, authcryptedTranscriptCredRequest);

                Console.WriteLine("\"Faber\" -> Create \"Transcript\" Credential for Alice");
                //    transcript_cred_values = json.dumps({
                //        "first_name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
                //        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
                //        "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
                //        "status": {"raw": "graduated", "encoded": "2213454313412354"},
                //        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
                //        "year": {"raw": "2015", "encoded": "2015"},
                //        "average": {"raw": "5", "encoded": "5"}
                //    })

                var transcriptCredValues = JsonConvert.SerializeObject(new Transcript()
                {
                    first_name = new CredValue { raw = "Alice", encoded = "1139481716457488690172217916278103335" },
                    last_name = new CredValue { raw = "Garcia", encoded = "5321642780241790123587902456789123452" },
                    degree = new CredValue { raw = "Bachelor of Science, Marketing", encoded = "12434523576212321" },
                    status = new CredValue { raw = "graduated", encoded = "2213454313412354" },
                    ssn = new CredValue { raw = "123-45-6789", encoded = "3124141231422543541" },
                    year = new CredValue { raw = "2015", encoded = "2015" },
                    average = new CredValue { raw = "5", encoded = "5" }
                });

                //    transcript_cred_json, _, _ = \
                //        await anoncreds.issuer_create_credential(faber_wallet, transcript_cred_offer_json,
                //                                                 authdecrypted_transcript_cred_request_json,
                //                                                 transcript_cred_values, None, None)

                IssuerCreateCredentialResult iccr = await AnonCreds.IssuerCreateCredentialAsync(faberWallet, transcriptCredOfferJson, faberTranscriptCredReqAlice.authdecryptedDidInfoJson, transcriptCredValues, null, null);

                Console.WriteLine("\"Faber\" -> Authcrypt \"Transcript\" Credential for Alice");
                //    authcrypted_transcript_cred_json = await crypto.auth_crypt(faber_wallet, faber_alice_key, alice_faber_verkey,
                //                                                               transcript_cred_json.encode('utf-8'))

                var authcryptedTranscriptCred = await Crypto.AuthCryptAsync(faberWallet, faberAliceKey, aliceFaberVerkey, Encoding.UTF8.GetBytes(iccr.CredentialJson));

                Console.WriteLine("\"Faber\" -> Send authcrypted \"Transcript\" Credential to Alice");

                Console.WriteLine("\"Alice\" -> Authdecrypted \"Transcript\" Credential from Faber");
                //    _, authdecrypted_transcript_cred_json, _ = \
                //        await auth_decrypt(alice_wallet, alice_faber_key, authcrypted_transcript_cred_json)

                AuthDecryptResult adr = await AuthDecrypt(aliceWallet, aliceFaberVerkey, authcryptedTranscriptCred);

                Console.WriteLine("\"Alice\" -> Store \"Transcript\" Credential from Faber");
                //    await anoncreds.prover_store_credential(alice_wallet, None, transcript_cred_request_metadata_json,
                //                                            authdecrypted_transcript_cred_json, faber_transcript_cred_def, None)

                await AnonCreds.ProverStoreCredentialAsync(aliceWallet, null, pccrr.CredentialRequestMetadataJson,
                                                                adr.authdecryptedDidInfoJson, faberTranscriptCredDefResult.ObjectJson, null);

                Console.WriteLine("==============================");
                Console.WriteLine("=== Apply for the job with Acme ==");
                Console.WriteLine("==============================");
                Console.WriteLine("== Apply for the job with Acme - Onboarding ==");
                Console.WriteLine("------------------------------");

                //    alice_wallet, acme_alice_key, alice_acme_did, alice_acme_key, acme_alice_connection_response = \
                //        await onboarding(pool_handle, "Acme", acme_wallet, acme_did, "Alice", alice_wallet, alice_wallet_config,
                //                         alice_wallet_credentials)

                OnboardingResult acmeAliceOnboarding = await Onboarding(pool, "Acme", acmeWallet, acmeDid, "Alice", aliceWallet, aliceWalletConfig, aliceWalletCredentials);

                var acmeAliceDid = acmeAliceOnboarding.toFromDid;
                var acmeAliceKey = acmeAliceOnboarding.fromToVarKey;
                var acmeAliceConnectionResponse = (JObject)JsonConvert.DeserializeObject(acmeAliceOnboarding.decryptedConnectionJson);
                
                Console.WriteLine("==============================");
                Console.WriteLine("== Apply for the job with Acme - Transcript proving ==");
                Console.WriteLine("------------------------------");

                Console.WriteLine("\"Acme\" -> Create \"Job-Application\" Proof Request");

                //    job_application_proof_request_json = json.dumps({
                //        'nonce': '1432422343242122312411212',
                //        'name': 'Job-Application',
                //        'version': '0.1',
                //        'requested_attributes': {
                //            'attr1_referent': {
                //                'name': 'first_name'
                //            },
                //            'attr2_referent': {
                //                'name': 'last_name'
                //            },
                //            'attr3_referent': {
                //                'name': 'degree',
                //                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
                //            },
                //            'attr4_referent': {
                //                'name': 'status',
                //                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
                //            },
                //            'attr5_referent': {
                //                'name': 'ssn',
                //                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
                //            },
                //            'attr6_referent': {
                //                'name': 'phone_number'
                //            }
                //        },
                //        'requested_predicates': {
                //            'predicate1_referent': {
                //                'name': 'average',
                //                'p_type': '>=',
                //                'p_value': 4,
                //                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
                //            }
                //        }
                //    })

                var jobApplicationProofRequestJson = "{" +
                           "                    \"nonce\":\"1432422343242122312411212\",\n" +
                           "                    \"name\":\"Job-Application\",\n" +
                           "                    \"version\":\"0.1\", " +
                           "                    \"requested_attributes\": {" +
                           "                          \"attr1_referent\":{\"name\":\"first_name\"}," +
                           "                          \"attr2_referent\":{\"name\":\"last_name\"}," +
                           "                          \"attr3_referent\":{\"name\":\"degree\"," +
                           "                                              \"restrictions\": [{\"cred_def_id\": \"" + faberTranscriptCredDefId + "\"}]" +
                           "                                             }," +
                           "                          \"attr4_referent\":{\"name\":\"status\"," +
                           "                                              \"restrictions\": [{\"cred_def_id\": \"" + faberTranscriptCredDefId + "\"}]" +
                           "                                             }," +
                           "                          \"attr5_referent\":{\"name\":\"ssn\"," +
                           "                                              \"restrictions\": [{\"cred_def_id\": \"" + faberTranscriptCredDefId + "\"}]" +
                           "                                             }," +
                           "                          \"attr6_referent\":{\"name\":\"phone_number\"}" +
                           "                     }," +
                           "                    \"requested_predicates\":{" +
                           "                         \"predicate1_referent\":{\"name\":\"average\",\"p_type\":\">=\",\"p_value\":4, \"restrictions\": [{\"cred_def_id\": \"" + faberTranscriptCredDefId + "\"}] }" +
                           "                    }" +
                           "                  }";

                Console.WriteLine("\"Acme\" -> Get key for Alice did");
                //    alice_acme_verkey = await did.key_for_did(pool_handle, acme_wallet, acme_alice_connection_response['did'])

                var aliceAcmeVerkey = await Did.KeyForDidAsync(pool, acmeWallet, (string)acmeAliceConnectionResponse.GetValue("did"));

                Console.WriteLine("\"Acme\" -> Authcrypt \"Job-Application\" Proof Request for Alice");
                //    authcrypted_job_application_proof_request_json = \
                //        await crypto.auth_crypt(acme_wallet, acme_alice_key, alice_acme_verkey,
                //                                job_application_proof_request_json.encode('utf-8'))

                var authcryptedJobApplicationProofRequestJson = await Crypto.AuthCryptAsync(acmeWallet, acmeAliceKey, aliceAcmeVerkey, Encoding.UTF8.GetBytes(jobApplicationProofRequestJson));

                Console.WriteLine("\"Acme\" -> Send authcrypted \"Job-Application\" Proof Request to Alice");

                Console.WriteLine("\"Alice\" -> Authdecrypt \"Job-Application\" Proof Request from Acme");
                //    acme_alice_verkey, authdecrypted_job_application_proof_request_json, _ = \
                //        await auth_decrypt(alice_wallet, alice_acme_key, authcrypted_job_application_proof_request_json)

                AuthDecryptResult aliceAuthDecrpytResult = await AuthDecrypt(aliceWallet, aliceAcmeVerkey, authcryptedJobApplicationProofRequestJson);

                Console.WriteLine("\"Alice\" -> Get credentials for \"Job-Application\" Proof Request");

                //    search_for_job_application_proof_request = \
                //        await anoncreds.prover_search_credentials_for_proof_req(alice_wallet,
                //                                                                authdecrypted_job_application_proof_request_json, None)

                var searchForJobApplicationProofRequest = await AnonCreds.ProverSearchCredentialsForProofRequestAsync(aliceWallet, aliceAuthDecrpytResult.authdecryptedDidInfoJson, null);

                //    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
                //    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
                //    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
                //    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
                //    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
                //    cred_for_predicate1 = \
                //        await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

                var credForAttr1 = await GetCredentialForReferent(searchForJobApplicationProofRequest, "attr1_referent");
                var credForAttr2 = await GetCredentialForReferent(searchForJobApplicationProofRequest, "attr2_referent");
                var credForAttr3 = await GetCredentialForReferent(searchForJobApplicationProofRequest, "attr3_referent");
                var credForAttr4 = await GetCredentialForReferent(searchForJobApplicationProofRequest, "attr4_referent");
                var credForAttr5 = await GetCredentialForReferent(searchForJobApplicationProofRequest, "attr5_referent");
                var credForPredicate1 = await GetCredentialForReferent(searchForJobApplicationProofRequest, "predicate1_referent");

                //    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

                await AnonCreds.ProverCloseCredentialsSearchForProofRequestAsync(searchForJobApplicationProofRequest);

                //    creds_for_job_application_proof = {cred_for_attr1['referent']: cred_for_attr1,
                //                                       cred_for_attr2['referent']: cred_for_attr2,
                //                                       cred_for_attr3['referent']: cred_for_attr3,
                //                                       cred_for_attr4['referent']: cred_for_attr4,
                //                                       cred_for_attr5['referent']: cred_for_attr5,
                //                                       cred_for_predicate1['referent']: cred_for_predicate1}

                Dictionary<string, string> credsForJobApplicationProof = new Dictionary<string, string>();
                // credsForJobApplicationProof.Add(

                //    schemas_json, cred_defs_json, revoc_states_json = \
                //        await prover_get_entities_from_ledger(pool_handle, alice_faber_did, creds_for_job_application_proof, 'Alice')

                ProverGetEntitiesFromLedgerResult pgeflr = await ProverGetEntitiesFromLedger(pool, aliceFaberDid, credsForJobApplicationProof, "Alice");

                //    logger.info("\"Alice\" -> Create \"Job-Application\" Proof")
                //    job_application_requested_creds_json = json.dumps({
                //        'self_attested_attributes': {
                //            'attr1_referent': 'Alice',
                //            'attr2_referent': 'Garcia',
                //            'attr6_referent': '123-45-6789'
                //        },
                //        'requested_attributes': {
                //            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
                //            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
                //            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
                //        },
                //        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
                //    })

                //    job_application_proof_json = \
                //        await anoncreds.prover_create_proof(alice_wallet, authdecrypted_job_application_proof_request_json,
                //                                            job_application_requested_creds_json, alice_master_secret_id,
                //                                            schemas_json, cred_defs_json, revoc_states_json)

                //    logger.info("\"Alice\" -> Authcrypt \"Job-Application\" Proof for Acme")
                //    authcrypted_job_application_proof_json = await crypto.auth_crypt(alice_wallet, alice_acme_key, acme_alice_verkey,
                //                                                                     job_application_proof_json.encode('utf-8'))

                //    logger.info("\"Alice\" -> Send authcrypted \"Job-Application\" Proof to Acme")

                //    logger.info("\"Acme\" -> Authdecrypted \"Job-Application\" Proof from Alice")
                //    _, decrypted_job_application_proof_json, decrypted_job_application_proof = \
                //        await auth_decrypt(acme_wallet, acme_alice_key, authcrypted_job_application_proof_json)

                //    schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json = \
                //        await verifier_get_entities_from_ledger(pool_handle, acme_did,
                //                                                decrypted_job_application_proof['identifiers'], 'Acme')

                //    logger.info("\"Acme\" -> Verify \"Job-Application\" Proof from Alice")
                //    assert 'Bachelor of Science, Marketing' == \
                //           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
                //    assert 'graduated' == \
                //           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
                //    assert '123-45-6789' == \
                //           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']

                //    assert 'Alice' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr1_referent']
                //    assert 'Garcia' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr2_referent']
                //    assert '123-45-6789' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr6_referent']

                //    assert await anoncreds.verifier_verify_proof(job_application_proof_request_json,
                //                                                 decrypted_job_application_proof_json,
                //                                                 schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json)

                //    logger.info("==============================")
                //    logger.info("== Apply for the job with Acme - Getting Job-Certificate Credential ==")
                //    logger.info("------------------------------")

                //    logger.info("\"Acme\" -> Create \"Job-Certificate\" Credential Offer for Alice")
                //    job_certificate_cred_offer_json = \
                //        await anoncreds.issuer_create_credential_offer(acme_wallet, acme_job_certificate_cred_def_id)

                //    logger.info("\"Acme\" -> Get key for Alice did")
                //    alice_acme_verkey = await did.key_for_did(pool_handle, acme_wallet, acme_alice_connection_response['did'])

                //    logger.info("\"Acme\" -> Authcrypt \"Job-Certificate\" Credential Offer for Alice")
                //    authcrypted_job_certificate_cred_offer = await crypto.auth_crypt(acme_wallet, acme_alice_key, alice_acme_verkey,
                //                                                                     job_certificate_cred_offer_json.encode('utf-8'))

                //    logger.info("\"Acme\" -> Send authcrypted \"Job-Certificate\" Credential Offer to Alice")

                //    logger.info("\"Alice\" -> Authdecrypted \"Job-Certificate\" Credential Offer from Acme")
                //    acme_alice_verkey, authdecrypted_job_certificate_cred_offer_json, authdecrypted_job_certificate_cred_offer = \
                //        await auth_decrypt(alice_wallet, alice_acme_key, authcrypted_job_certificate_cred_offer)

                //    logger.info("\"Alice\" -> Get \"Acme Job-Certificate\" Credential Definition from Ledger")
                //    (_, acme_job_certificate_cred_def) = \
                //        await get_cred_def(pool_handle, alice_acme_did, authdecrypted_job_certificate_cred_offer['cred_def_id'])

                //    logger.info("\"Alice\" -> Create and store in Wallet \"Job-Certificate\" Credential Request for Acme")
                //    (job_certificate_cred_request_json, job_certificate_cred_request_metadata_json) = \
                //        await anoncreds.prover_create_credential_req(alice_wallet, alice_acme_did,
                //                                                     authdecrypted_job_certificate_cred_offer_json,
                //                                                     acme_job_certificate_cred_def, alice_master_secret_id)

                //    logger.info("\"Alice\" -> Authcrypt \"Job-Certificate\" Credential Request for Acme")
                //    authcrypted_job_certificate_cred_request_json = \
                //        await crypto.auth_crypt(alice_wallet, alice_acme_key, acme_alice_verkey,
                //                                job_certificate_cred_request_json.encode('utf-8'))

                //    logger.info("\"Alice\" -> Send authcrypted \"Job-Certificate\" Credential Request to Acme")

                //    logger.info("\"Acme\" -> Authdecrypt \"Job-Certificate\" Credential Request from Alice")
                //    alice_acme_verkey, authdecrypted_job_certificate_cred_request_json, _ = \
                //        await auth_decrypt(acme_wallet, acme_alice_key, authcrypted_job_certificate_cred_request_json)

                //    logger.info("\"Acme\" -> Create \"Job-Certificate\" Credential for Alice")
                //    alice_job_certificate_cred_values_json = json.dumps({
                //        "first_name": {"raw": "Alice", "encoded": "245712572474217942457235975012103335"},
                //        "last_name": {"raw": "Garcia", "encoded": "312643218496194691632153761283356127"},
                //        "employee_status": {"raw": "Permanent", "encoded": "2143135425425143112321314321"},
                //        "salary": {"raw": "2400", "encoded": "2400"},
                //        "experience": {"raw": "10", "encoded": "10"}
                //    })

                //    job_certificate_cred_json, _, _ = \
                //        await anoncreds.issuer_create_credential(acme_wallet, job_certificate_cred_offer_json,
                //                                                 authdecrypted_job_certificate_cred_request_json,
                //                                                 alice_job_certificate_cred_values_json, None, None)

                //    logger.info("\"Acme\" -> Authcrypt \"Job-Certificate\" Credential for Alice")
                //    authcrypted_job_certificate_cred_json = \
                //        await crypto.auth_crypt(acme_wallet, acme_alice_key, alice_acme_verkey,
                //                                job_certificate_cred_json.encode('utf-8'))

                //    logger.info("\"Acme\" -> Send authcrypted \"Job-Certificate\" Credential to Alice")

                //    logger.info("\"Alice\" -> Authdecrypted \"Job-Certificate\" Credential from Acme")
                //    _, authdecrypted_job_certificate_cred_json, _ = \
                //        await auth_decrypt(alice_wallet, alice_acme_key, authcrypted_job_certificate_cred_json)

                //    logger.info("\"Alice\" -> Store \"Job-Certificate\" Credential")
                //    await anoncreds.prover_store_credential(alice_wallet, None, job_certificate_cred_request_metadata_json,
                //                                            authdecrypted_job_certificate_cred_json,
                //                                            acme_job_certificate_cred_def_json, None)

                //    logger.info("==============================")
                //    logger.info("=== Apply for the loan with Thrift ==")
                //    logger.info("==============================")
                //    logger.info("== Apply for the loan with Thrift - Onboarding ==")
                //    logger.info("------------------------------")

                //    _, thrift_alice_key, alice_thrift_did, alice_thrift_key, \
                //    thrift_alice_connection_response = await onboarding(pool_handle, "Thrift", thrift_wallet, thrift_did, "Alice",
                //                                                        alice_wallet, alice_wallet_config, alice_wallet_credentials)

                //    logger.info("==============================")
                //    logger.info("== Apply for the loan with Thrift - Job-Certificate proving  ==")
                //    logger.info("------------------------------")

                //    logger.info("\"Thrift\" -> Create \"Loan-Application-Basic\" Proof Request")
                //    apply_loan_proof_request_json = json.dumps({
                //        'nonce': '123432421212',
                //        'name': 'Loan-Application-Basic',
                //        'version': '0.1',
                //        'requested_attributes': {
                //            'attr1_referent': {
                //                'name': 'employee_status',
                //                'restrictions': [{'cred_def_id': acme_job_certificate_cred_def_id}]
                //            }
                //        },
                //        'requested_predicates': {
                //            'predicate1_referent': {
                //                'name': 'salary',
                //                'p_type': '>=',
                //                'p_value': 2000,
                //                'restrictions': [{'cred_def_id': acme_job_certificate_cred_def_id}]
                //            },
                //            'predicate2_referent': {
                //                'name': 'experience',
                //                'p_type': '>=',
                //                'p_value': 1,
                //                'restrictions': [{'cred_def_id': acme_job_certificate_cred_def_id}]
                //            }
                //        }
                //    })

                //    logger.info("\"Thrift\" -> Get key for Alice did")
                //    alice_thrift_verkey = await did.key_for_did(pool_handle, thrift_wallet, thrift_alice_connection_response['did'])

                //    logger.info("\"Thrift\" -> Authcrypt \"Loan-Application-Basic\" Proof Request for Alice")
                //    authcrypted_apply_loan_proof_request_json = \
                //        await crypto.auth_crypt(thrift_wallet, thrift_alice_key, alice_thrift_verkey,
                //                                apply_loan_proof_request_json.encode('utf-8'))

                //    logger.info("\"Thrift\" -> Send authcrypted \"Loan-Application-Basic\" Proof Request to Alice")

                //    logger.info("\"Alice\" -> Authdecrypt \"Loan-Application-Basic\" Proof Request from Thrift")
                //    thrift_alice_verkey, authdecrypted_apply_loan_proof_request_json, _ = \
                //        await auth_decrypt(alice_wallet, alice_thrift_key, authcrypted_apply_loan_proof_request_json)

                //    logger.info("\"Alice\" -> Get credentials for \"Loan-Application-Basic\" Proof Request")

                //    search_for_apply_loan_proof_request = \
                //        await anoncreds.prover_search_credentials_for_proof_req(alice_wallet,
                //                                                                authdecrypted_apply_loan_proof_request_json, None)

                //    cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'attr1_referent')
                //    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate1_referent')
                //    cred_for_predicate2 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate2_referent')

                //    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_proof_request)

                //    creds_for_apply_loan_proof = {cred_for_attr1['referent']: cred_for_attr1,
                //                                  cred_for_predicate1['referent']: cred_for_predicate1,
                //                                  cred_for_predicate2['referent']: cred_for_predicate2}

                //    schemas_json, cred_defs_json, revoc_states_json = \
                //        await prover_get_entities_from_ledger(pool_handle, alice_thrift_did, creds_for_apply_loan_proof, 'Alice')

                //    logger.info("\"Alice\" -> Create \"Loan-Application-Basic\" Proof")
                //    apply_loan_requested_creds_json = json.dumps({
                //        'self_attested_attributes': {},
                //        'requested_attributes': {
                //            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True}
                //        },
                //        'requested_predicates': {
                //            'predicate1_referent': {'cred_id': cred_for_predicate1['referent']},
                //            'predicate2_referent': {'cred_id': cred_for_predicate2['referent']}
                //        }
                //    })
                //    alice_apply_loan_proof_json = \
                //        await anoncreds.prover_create_proof(alice_wallet, authdecrypted_apply_loan_proof_request_json,
                //                                            apply_loan_requested_creds_json, alice_master_secret_id, schemas_json,
                //                                            cred_defs_json, revoc_states_json)

                //    logger.info("\"Alice\" -> Authcrypt \"Loan-Application-Basic\" Proof for Thrift")
                //    authcrypted_alice_apply_loan_proof_json = \
                //        await crypto.auth_crypt(alice_wallet, alice_thrift_key, thrift_alice_verkey,
                //                                alice_apply_loan_proof_json.encode('utf-8'))

                //    logger.info("\"Alice\" -> Send authcrypted \"Loan-Application-Basic\" Proof to Thrift")

                //    logger.info("\"Thrift\" -> Authdecrypted \"Loan-Application-Basic\" Proof from Alice")
                //    _, authdecrypted_alice_apply_loan_proof_json, authdecrypted_alice_apply_loan_proof = \
                //        await auth_decrypt(thrift_wallet, thrift_alice_key, authcrypted_alice_apply_loan_proof_json)

                //    logger.info("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                //                " required for Proof verifying")

                //    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
                //        await verifier_get_entities_from_ledger(pool_handle, thrift_did,
                //                                                authdecrypted_alice_apply_loan_proof['identifiers'], 'Thrift')

                //    logger.info("\"Thrift\" -> Verify \"Loan-Application-Basic\" Proof from Alice")
                //    assert 'Permanent' == \
                //           authdecrypted_alice_apply_loan_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']

                //    assert await anoncreds.verifier_verify_proof(apply_loan_proof_request_json,
                //                                                 authdecrypted_alice_apply_loan_proof_json,
                //                                                 schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

                //    logger.info("==============================")

                //    logger.info("==============================")
                //    logger.info("== Apply for the loan with Thrift - Transcript and Job-Certificate proving  ==")
                //    logger.info("------------------------------")

                //    logger.info("\"Thrift\" -> Create \"Loan-Application-KYC\" Proof Request")
                //    apply_loan_kyc_proof_request_json = json.dumps({
                //        'nonce': '123432421212',
                //        'name': 'Loan-Application-KYC',
                //        'version': '0.1',
                //        'requested_attributes': {
                //            'attr1_referent': {'name': 'first_name'},
                //            'attr2_referent': {'name': 'last_name'},
                //            'attr3_referent': {'name': 'ssn'}
                //        },
                //        'requested_predicates': {}
                //    })

                //    logger.info("\"Thrift\" -> Get key for Alice did")
                //    alice_thrift_verkey = await did.key_for_did(pool_handle, thrift_wallet, thrift_alice_connection_response['did'])

                //    logger.info("\"Thrift\" -> Authcrypt \"Loan-Application-KYC\" Proof Request for Alice")
                //    authcrypted_apply_loan_kyc_proof_request_json = \
                //        await crypto.auth_crypt(thrift_wallet, thrift_alice_key, alice_thrift_verkey,
                //                                apply_loan_kyc_proof_request_json.encode('utf-8'))

                //    logger.info("\"Thrift\" -> Send authcrypted \"Loan-Application-KYC\" Proof Request to Alice")

                //    logger.info("\"Alice\" -> Authdecrypt \"Loan-Application-KYC\" Proof Request from Thrift")
                //    thrift_alice_verkey, authdecrypted_apply_loan_kyc_proof_request_json, _ = \
                //        await auth_decrypt(alice_wallet, alice_thrift_key, authcrypted_apply_loan_kyc_proof_request_json)

                //    logger.info("\"Alice\" -> Get credentials for \"Loan-Application-KYC\" Proof Request")

                //    search_for_apply_loan_kyc_proof_request = \
                //        await anoncreds.prover_search_credentials_for_proof_req(alice_wallet,
                //                                                                authdecrypted_apply_loan_kyc_proof_request_json, None)

                //    cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr1_referent')
                //    cred_for_attr2 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr2_referent')
                //    cred_for_attr3 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr3_referent')

                //    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_kyc_proof_request)

                //    creds_for_apply_loan_kyc_proof = {cred_for_attr1['referent']: cred_for_attr1,
                //                                      cred_for_attr2['referent']: cred_for_attr2,
                //                                      cred_for_attr3['referent']: cred_for_attr3}

                //    schemas_json, cred_defs_json, revoc_states_json = \
                //        await prover_get_entities_from_ledger(pool_handle, alice_thrift_did, creds_for_apply_loan_kyc_proof, 'Alice')

                //    logger.info("\"Alice\" -> Create \"Loan-Application-KYC\" Proof")

                //    apply_loan_kyc_requested_creds_json = json.dumps({
                //        'self_attested_attributes': {},
                //        'requested_attributes': {
                //            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
                //            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
                //            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True}
                //        },
                //        'requested_predicates': {}
                //    })

                //    alice_apply_loan_kyc_proof_json = \
                //        await anoncreds.prover_create_proof(alice_wallet, authdecrypted_apply_loan_kyc_proof_request_json,
                //                                            apply_loan_kyc_requested_creds_json, alice_master_secret_id,
                //                                            schemas_json, cred_defs_json, revoc_states_json)

                //    logger.info("\"Alice\" -> Authcrypt \"Loan-Application-KYC\" Proof for Thrift")
                //    authcrypted_alice_apply_loan_kyc_proof_json = \
                //        await crypto.auth_crypt(alice_wallet, alice_thrift_key, thrift_alice_verkey,
                //                                alice_apply_loan_kyc_proof_json.encode('utf-8'))

                //    logger.info("\"Alice\" -> Send authcrypted \"Loan-Application-KYC\" Proof to Thrift")

                //    logger.info("\"Thrift\" -> Authdecrypted \"Loan-Application-KYC\" Proof from Alice")
                //    _, authdecrypted_alice_apply_loan_kyc_proof_json, authdecrypted_alice_apply_loan_kyc_proof = \
                //        await auth_decrypt(thrift_wallet, thrift_alice_key, authcrypted_alice_apply_loan_kyc_proof_json)

                //    logger.info("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                //                " required for Proof verifying")

                //    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
                //        await verifier_get_entities_from_ledger(pool_handle, thrift_did,
                //                                                authdecrypted_alice_apply_loan_kyc_proof['identifiers'], 'Thrift')

                //    logger.info("\"Thrift\" -> Verify \"Loan-Application-KYC\" Proof from Alice")
                //    assert 'Alice' == \
                //           authdecrypted_alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
                //    assert 'Garcia' == \
                //           authdecrypted_alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
                //    assert '123-45-6789' == \
                //           authdecrypted_alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']

                //    assert await anoncreds.verifier_verify_proof(apply_loan_kyc_proof_request_json,
                //                                                 authdecrypted_alice_apply_loan_kyc_proof_json,
                //                                                 schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

                //    logger.info("==============================")

                //    logger.info(" \"Sovrin Steward\" -> Close and Delete wallet")
                //    await wallet.close_wallet(steward_wallet)
                //    await wallet.delete_wallet(steward_wallet_config, steward_wallet_credentials)

                Console.WriteLine("==============================");

                Console.WriteLine(" \"Sovrin Steward\" -> Close and Delete wallet");
                await stewardWallet.CloseAsync();
                await Wallet.DeleteWalletAsync(stewardWalletConfig, stewardWalletCredentials);

                Console.WriteLine("\"Government\" -> Close and Delete wallet");
                //    await wallet.close_wallet(government_wallet)
                //    await wallet.delete_wallet(government_wallet_config, government_wallet_credentials)

                await governmentWallet.CloseAsync();
                await Wallet.DeleteWalletAsync(governmentWalletConfig, governmentWalletCredentials);

                Console.WriteLine("\"Faber\" -> Close and Delete wallet");
                //    await wallet.close_wallet(faber_wallet)
                //    await wallet.delete_wallet(faber_wallet_config, faber_wallet_credentials)

                await faberWallet.CloseAsync();
                await Wallet.DeleteWalletAsync(faberWalletConfig, faberWalletCredentials);

                Console.WriteLine("\"Acme\" -> Close and Delete wallet");
                //    await wallet.close_wallet(acme_wallet)
                //    await wallet.delete_wallet(acme_wallet_config, acme_wallet_credentials)

                await acmeWallet.CloseAsync();
                await Wallet.DeleteWalletAsync(acmeWalletConfig, acmeWalletCredentials);

                Console.WriteLine("\"Thrift\" -> Close and Delete wallet");
                //    await wallet.close_wallet(thrift_wallet)
                //    await wallet.delete_wallet(thrift_wallet_config, thrift_wallet_credentials)

                await thriftWallet.CloseAsync();
                await Wallet.DeleteWalletAsync(thriftWalletConfig, thriftWalletCredentials);

                Console.WriteLine("\"Alice\" -> Close and Delete wallet");
                //    await wallet.close_wallet(alice_wallet)
                //    await wallet.delete_wallet(alice_wallet_config, alice_wallet_credentials)

                await aliceWallet.CloseAsync();
                await Wallet.DeleteWalletAsync(aliceWalletConfig, aliceWalletCredentials);

                //    logger.info("Close and Delete pool")
                //    await pool.close_pool_ledger(pool_handle)
                //    await pool.delete_pool_ledger_config(pool_name)

                Console.WriteLine("Close and Delete pool");

            }  // end of POOL using statement

            Console.WriteLine("Getting started -> done");
        }

        //async def onboarding(pool_handle, _from, from_wallet, from_did, to, to_wallet: Optional[str], to_wallet_config: str,
        //                     to_wallet_credentials: str):
        public static async Task<OnboardingResult> Onboarding(Pool pool, string from, Wallet fromWallet, string fromDid, string to, Wallet toWallet, string toWalletConfig, string toWalletCredentials)
        {

            Console.WriteLine("\"{0}\" -> Create and store in Wallet \"{1} {2}\" DID", from, from, to);
            //    (from_to_did, from_to_key) = await did.create_and_store_my_did(from_wallet, "{}")
            var _fromToDidResult = await Did.CreateAndStoreMyDidAsync(fromWallet, "{}");
            var _fromToDid = _fromToDidResult.Did;
            var _fromToVarKey = _fromToDidResult.VerKey;

            Console.WriteLine("\"{0}\" -> Send Nym to Ledger for \"{1} {2}\" DID", from, from, to);
            //    await send_nym(pool_handle, from_wallet, from_did, from_to_did, from_to_key, None)

            await SendNym(pool, fromWallet, fromDid, _fromToDid, _fromToVarKey, null);

            Console.WriteLine("\"{0}\" -> Send connection request to {1} with \"{2} {3}\" DID and nonce", from, to, from, to);
            //    connection_request = {
            //        'did': from_to_did,
            //        'nonce': 123456789
            //    }

            var connectionRequest = new Dictionary<string, string> { { "did", _fromToDid }, { "nonce", "123456789" } };

            if (toWallet is null)
            {
                //    if not to_wallet:
                //        logger.info("\"{}\" -> Create wallet".format(to))
                //        try:
                //            await wallet.create_wallet(to_wallet_config, to_wallet_credentials)
                //        except IndyError as ex:
                //            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                //                pass
                //        to_wallet = await wallet.open_wallet(to_wallet_config, to_wallet_credentials)

                Console.WriteLine("\"{0}\" -> Create wallet", to);
                await WalletUtils.CreateWalletAsync(toWalletConfig, toWalletCredentials);
                toWallet = await Wallet.OpenWalletAsync(toWalletConfig, toWalletCredentials);
            }

            Console.WriteLine("\"{0}\" -> Create and store in Wallet \"{1} {2}\" DID", to, to, from);
            //    (to_from_did, to_from_key) = await did.create_and_store_my_did(to_wallet, "{}")

            var toFromDidResult = await Did.CreateAndStoreMyDidAsync(toWallet, "{}");
            var toFromDid = toFromDidResult.Did;
            var toFromVerKey = toFromDidResult.VerKey;

            Console.WriteLine("\"{0}\" -> Get key for did from \"{1}\" connection request", to, from);
            //    from_to_verkey = await did.key_for_did(pool_handle, to_wallet, connection_request['did'])
            var _fromToVerKey = await Did.KeyForDidAsync(pool, toWallet, connectionRequest["did"]);

            Console.WriteLine("\"{0}\" -> Anoncrypt connection response for \"{1}\" with \"{2} {3}\" DID, verkey and nonce", to, from, to, from);
            //    connection_response = json.dumps({
            //        'did': to_from_did,
            //        'verkey': to_from_key,
            //        'nonce': connection_request['nonce']
            //    })
            //    anoncrypted_connection_response = await crypto.anon_crypt(from_to_verkey, connection_response.encode('utf-8'))

            var anoncryptedConnectionJson = JsonConvert.SerializeObject(new { did = toFromDid, verKey = toFromVerKey, nounce = connectionRequest["nonce"] });
            var anoncryptedConnectionResponse = await Crypto.AnonCryptAsync(_fromToVarKey, Encoding.UTF8.GetBytes(anoncryptedConnectionJson));

            //    logger.info("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to, _from))

            Console.WriteLine("\"{0}\" -> Send anoncrypted connection response to \"{1}\"", to, from);

            //    logger.info("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from, to))
            //    decrypted_connection_response = \
            //        json.loads((await crypto.anon_decrypt(from_wallet, from_to_key,
            //                                              anoncrypted_connection_response)).decode("utf-8"))

            Console.WriteLine("\"{0}\" -> Anondecrypt connection response from \"{1}\"", from, to);
            var decryptedConnectionResponse = await Crypto.AnonDecryptAsync(fromWallet, _fromToVarKey, anoncryptedConnectionResponse);
            var decryptedConnectionJson = Encoding.UTF8.GetString(decryptedConnectionResponse);

            //    logger.info("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from, to))
            //    assert connection_request['nonce'] == decrypted_connection_response['nonce']

            Console.WriteLine("\"{0}\" -> Authenticates \"{1}\" by comparision of Nonce", from, to);

            //    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, to, _from))
            //    await send_nym(pool_handle, from_wallet, from_did, to_from_did, to_from_key, None)

            Console.WriteLine("\"{0}\" -> Send Nym to Ledger for \"{1} {2}\" DID", from, to, from);
            await SendNym(pool, fromWallet, fromDid, toFromDid, toFromVerKey, null);

            //    return to_wallet, from_to_key, to_from_did, to_from_key, decrypted_connection_response

            return new OnboardingResult { toWallet = toWallet, fromToVarKey = _fromToVarKey, toFromDid = toFromDid, toFromVarKey = toFromVerKey, decryptedConnectionJson = decryptedConnectionJson };
        }

        //async def get_verinym(pool_handle, _from, from_wallet, from_did, from_to_key,
        //                      to, to_wallet, to_from_did, to_from_key, role):
        public static async Task<string> GetVerinym(Pool pool, string from, Wallet fromWallet, string fromDid, string fromToVerKey, string to, Wallet toWallet, string toFromDid, string toFromVerKey, string role)
        {
            Console.WriteLine("\"{0}\" -> Create and store in Wallet \"{1}\" new DID", to, to);
            //    (to_did, to_key) = await did.create_and_store_my_did(to_wallet, "{}")

            var _toDidResult = await Did.CreateAndStoreMyDidAsync(toWallet, "{}");
            var _toDid = _toDidResult.Did;
            var _toVarKey = _toDidResult.VerKey;

            Console.WriteLine("\"{0}\" -> Authcrypt \"{1} DID info\" for \"{2}\"", to, to, from);
            //    did_info_json = json.dumps({
            //        'did': to_did,
            //        'verkey': to_key
            //    })
            //    authcrypted_did_info_json = \
            //        await crypto.auth_crypt(to_wallet, to_from_key, from_to_key, did_info_json.encode('utf-8'))

            var didInfoJson = JsonConvert.SerializeObject(new { did = _toDid, verkey = _toVarKey });
            var authcryptedDidInfo = await Crypto.AuthCryptAsync(toWallet, toFromVerKey, fromToVerKey, Encoding.UTF8.GetBytes(didInfoJson));

            Console.WriteLine("\"{0}\" -> Send authcrypted \"{1} DID info\" to {2}", to, to, from);

            Console.WriteLine("\"{0}\" -> Authdecrypted \"{1} DID info\" from {2}", from, to, to);
            //    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
            //        await auth_decrypt(from_wallet, from_to_key, authcrypted_did_info_json)
            AuthDecryptResult authDecryptResult = await AuthDecrypt(fromWallet, fromToVerKey, authcryptedDidInfo);

            //    logger.info("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from, to, ))
            //    assert sender_verkey == await did.key_for_did(pool_handle, from_wallet, to_from_did)

            Console.WriteLine("\"{0}\" -> Authenticate {1} by comparision of Verkeys", from, to);
            var _toVerkey = await Did.KeyForDidAsync(pool, fromWallet, toFromDid);
            Console.WriteLine("asset that {0} == {1}", authDecryptResult.authcryptedDidInfo["verykey"], _toVarKey);

            Console.WriteLine("\"{0}\" -> Send Nym to Ledger for \"{1} DID\" with {2} Role", from, to, role);
            //    await send_nym(pool_handle, from_wallet, from_did, authdecrypted_did_info['did'],
            //                   authdecrypted_did_info['verkey'], role)
            await SendNym(pool, fromWallet, fromDid,
                (string)authDecryptResult.authcryptedDidInfo["did"],
                (string)authDecryptResult.authcryptedDidInfo["verkey"],
                role);

            //    return to_did
            return _toDid;
        }

        //async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
        //    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
        //    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)

        public static async Task SendNym(Pool pool, Wallet wallet, string did, string newDid, string newKey, string role)
        {
            var nymRequest = await Ledger.BuildNymRequestAsync(did, newDid, newKey, null, role);
            await Ledger.SignAndSubmitRequestAsync(pool, wallet, did, nymRequest);
        }

        //async def send_schema(pool_handle, wallet_handle, _did, schema):
        //    schema_request = await ledger.build_schema_request(_did, schema)
        //    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)

        public static async Task SendSchema(Pool pool, Wallet wallet, string did, string schema)
        {
            var schemaRequest = await Ledger.BuildSchemaRequestAsync(did, schema);
            await Ledger.SignAndSubmitRequestAsync(pool, wallet, did, schemaRequest);
        }

        //async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
        //    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
        //    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)

        public static async Task SendCredDef(Pool pool, Wallet wallet, string did, string credDefJson)
        {
            var credDefRequest = await Ledger.BuildCredDefRequestAsync(did, credDefJson);
            await Ledger.SignAndSubmitRequestAsync(pool, wallet, did, credDefRequest);
        }

        //async def get_schema(pool_handle, _did, schema_id):
        //    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
        //    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
        //    return await ledger.parse_get_schema_response(get_schema_response)

        public static async Task<ParseResponseResult> GetSchema(Pool pool, string did, string schemaId)
        {
            var getSchemaRequest = await Ledger.BuildGetSchemaRequestAsync(did, schemaId);
            var getSchemaResponse = await Ledger.SubmitRequestAsync(pool, getSchemaRequest);
            return await Ledger.ParseGetSchemaResponseAsync(getSchemaResponse);
        }


        //async def get_cred_def(pool_handle, _did, schema_id):
        //    get_cred_def_request = await ledger.build_get_cred_def_request(_did, schema_id)
        //    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
        //    return await ledger.parse_get_cred_def_response(get_cred_def_response)

        public static async Task<ParseResponseResult> GetCredDef(Pool pool, string did, string schemaId)
        {
            var getRequest = await Ledger.BuildGetCredDefRequestAsync(did, schemaId);
            var getResponse = await Ledger.SubmitRequestAsync(pool, getRequest);
            return await Ledger.ParseGetCredDefResponseAsync(getResponse);
        }


        //async def get_credential_for_referent(search_handle, referent):
        //    credentials = json.loads(
        //        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
        //    return credentials[0]['cred_info']

        public static async Task<string> GetCredentialForReferent(CredentialSearchForProofRequest searchHandle, string referent)
        {
            var credentialsJson = await AnonCreds.ProverFetchCredentialsForProofRequestAsync(searchHandle, referent, 10);
            var credentials = JArray.Parse(credentialsJson);
            var credInfoJson =  JsonConvert.SerializeObject(credentials[0]["cred_info"]);
            return credInfoJson;
        }

        //async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
        //    schemas = {}
        //    cred_defs = {}
        //    rev_states = {}
        //    for item in identifiers.values():
        //        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        //        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        //        schemas[received_schema_id] = json.loads(received_schema)

        //        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        //        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        //        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        //        if 'rev_reg_seq_no' in item:
        //            pass  # TODO Create Revocation States

        //    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)

        public static async Task<ProverGetEntitiesFromLedgerResult> ProverGetEntitiesFromLedger(Pool pool, string did, Dictionary<string,string> identifiers, string actor)
        {
            ProverGetEntitiesFromLedgerResult _results = new ProverGetEntitiesFromLedgerResult();

            foreach (var item in identifiers)
            {
                Console.WriteLine("\"{0}\" -> Get Schema from Ledger", actor);
                //ParseResponseResult _getSchema = await GetSchema(pool, did, item["schema_id"]);
                //_results.schemas.add(

                Console.WriteLine("\"{0}\" -> Get Claim Definition from Ledger", actor);
                //ParseResponseResult _getCredDef = await GetCredDef(pool, did, item["cred_def_id"]);
                //_results.credDefs.add(
            }
            return _results;
        }


        //async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
        //    schemas = {}
        //    cred_defs = {}
        //    rev_reg_defs = {}
        //    rev_regs = {}
        //    for item in identifiers:
        //        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        //        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        //        schemas[received_schema_id] = json.loads(received_schema)

        //        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        //        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        //        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        //        if 'rev_reg_seq_no' in item:
        //            pass  # TODO Get Revocation Definitions and Revocation Registries

        //    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


        //async def auth_decrypt(wallet_handle, key, message):
        //    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
        //    decrypted_message_json = decrypted_message_json.decode("utf-8")
        //    decrypted_message = json.loads(decrypted_message_json)
        //    return from_verkey, decrypted_message_json, decrypted_message

        public static async Task<AuthDecryptResult> AuthDecrypt(Wallet wallet, string key, byte[] message)
        {
            var _authDecryptResult = await Crypto.AuthDecryptAsync(wallet, key, message);
            var _decryptedMessageJson = Encoding.UTF8.GetString(_authDecryptResult.MessageData);
            var _authcryptedDidInfo = (JObject)JsonConvert.DeserializeObject(_decryptedMessageJson);

            return new AuthDecryptResult { verKey = _authDecryptResult.TheirVk, authdecryptedDidInfoJson = _decryptedMessageJson, authcryptedDidInfo = _authcryptedDidInfo };
        }

        //if __name__ == '__main__':
        //    run_coroutine(run)
        //    time.sleep(1)  # FIXME waiting for libindy thread complete

    }

    public class ProverGetEntitiesFromLedgerResult
    {
        public string schemas { get; set; }
        public string credDefs { get; set; }
        public string revRegDefs { get; set; }
        public string revRegs { get; set; }
    }

    public class Transcript
    {
        public CredValue first_name { get; set; }
        public CredValue last_name { get; set; }
        public CredValue degree { get; set; }
        public CredValue status { get; set; }
        public CredValue ssn { get; set; }
        public CredValue year { get; set; }
        public CredValue average { get; set; }
    }

    public class CredValue
    {
        public string raw { get; set; }
        public string encoded { get; set; }
    }

    public class AuthDecryptResult
    {
        public string verKey { get; set; }
        public string authdecryptedDidInfoJson { get; set; }
        public JObject authcryptedDidInfo { set; get; }
    }

    public class OnboardingResult
    {
        public Wallet toWallet { get; set; }
        public string fromToVarKey { get; set; }
        public string toFromDid { get; set; }
        public string toFromVarKey { get; set; }
        public string decryptedConnectionJson { get; set; }
    }
}
