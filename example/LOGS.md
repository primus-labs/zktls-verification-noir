"Small" commitment example passes, has a ~400k circuit.
"Large" commitment and hash example fail, havce 3.9M and 2.5M gates respectively. In previous version ` devnet.5` these numbers were 711.763 and 794.646. 
```
# yarn tsx devnet-verify-comm-small.ts
yarn run v1.22.22
$ xx/zktls-verification-noir/example/js_test/node_modules/.bin/tsx devnet-verify-comm-small.ts
======================================================================
TEST 1b: verify_comm — BusinessProgramSmallComm (MAX_COMMS=1)
======================================================================
[12:16:33.136] INFO: kv-store:lmdb-v2 Starting data store with maxReaders 16
🔑 Secret key: 0x24350f028a213ec7421f4fca5aa5c3c3ce3318850708732a4b591b94300f542f
🧂 Salt: 0x1632ced6fd98cd0a2739f451002b9e4f0059f3d8d64cd4282e021000d8d49357
⚠️  Save these if you want to reuse this account!
[12:16:33.455] INFO: embedded-wallet:pxe:service Started PXE connected to chain 11155111 version 615022430
[12:16:33.456] INFO: kv-store:lmdb-v2 Starting data store with maxReaders 16
Account address: 0x2b28f6497b4c914442d0aaa221d5907eac1f1f34d427838dae9ede49e1c57458
[12:16:33.641] INFO: embedded-wallet:pxe:service Added contract SchnorrAccount at 0x2b28f6497b4c914442d0aaa221d5907eac1f1f34d427838dae9ede49e1c57458 with class 0x0a167ca249952af052a802e0520f2ab08870fa28619c00a95e9e1bf3caf0fb2b
[12:16:33.644] INFO: embedded-wallet:pxe:service Registered account 0x2b28f6497b4c914442d0aaa221d5907eac1f1f34d427838dae9ede49e1c57458
[12:16:33.646] INFO: embedded-wallet:wallet:db Account stored in database
⏳ Deploying account on-chain (~2-5 min)...
[12:16:33.814] INFO: embedded-wallet:pxe:service Added contract SponsoredFPC at 0x09a4df73aa47f82531a038d1d51abfc85b27665c4b7ca751e2d4fa9f19caffb2 with class 0x2a70a2847b3af93b7a60f922c6e8ddda9066fa38ee9713ade9104d2556bf5e1a
[12:16:38.545] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 2146.9416249999995ms
[12:16:38.545] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
[12:16:41.619] INFO: embedded-wallet:pxe:prover Generated ClientIVC proof {"eventName":"client-ivc-proof-generation","duration":3073.8314999999993,"proofSize":3216}
[12:16:42.446] INFO: embedded-wallet Sent transaction 0x00dc76783371a37c7b04f8c970ffa6bbc8b28c75c812a31b8293a553fd448805
✅ Account deployed!

Commitments in test data: 1

Deploying BusinessProgramSmallComm contract...
[12:17:15.812] INFO: embedded-wallet:pxe:service Added contract BusinessProgramSmallComm at 0x1acee616ee1ea1de9b450357029d3d4fbc96b8e48f842fdb252d7f6e571b6a48 with class 0x1219180ea71842c33a0e1f30fc2f8d2b580c127e410d8a82aa2acb36ecdcc6d2
[12:17:16.014] INFO: embedded-wallet:pxe:service Registered account 0x2b28f6497b4c914442d0aaa221d5907eac1f1f34d427838dae9ede49e1c57458
[12:17:20.455] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 2027.5469999999987ms
[12:17:20.455] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
[12:17:23.136] INFO: embedded-wallet:pxe:prover Generated ClientIVC proof {"eventName":"client-ivc-proof-generation","duration":2680.6353329999984,"proofSize":4719}
[12:17:24.240] INFO: embedded-wallet Sent transaction 0x1f84d47c943fab09874125ce36752e45e3c1ffcef524084f549c8d7bc1f73d64
Contract deployed at: 0x1acee616ee1ea1de9b450357029d3d4fbc96b8e48f842fdb252d7f6e571b6a48

Profiling verify_comm (small)...
[12:17:49.963] INFO: embedded-wallet:pxe:service Registered account 0x2b28f6497b4c914442d0aaa221d5907eac1f1f34d427838dae9ede49e1c57458
[12:17:50.191] INFO: embedded-wallet:pxe:service Profiling transaction execution request to 0x9d57a239 at 0x2b28f6497b4c914442d0aaa221d5907eac1f1f34d427838dae9ede49e1c57458 {"origin":{"xCoord":{"asBigInt":"19521826182333917150243958762064409027977868209862974201312287926997215442008"}},"functionSelector":{"value":2639766073},"simulatePublic":false,"chainId":{"asBigInt":"11155111"},"version":{"asBigInt":"615022430"},"authWitnesses":[{"asBigInt":"19740813439161866802630589151335019310217522018289543274557449665939623201771"}]}
  SchnorrAccount:entrypoint: 54,352 gates
  private_kernel_init: 46,811 gates
  BusinessProgramSmallComm:verify_comm: 396,142 gates
  private_kernel_inner: 101,237 gates
  private_kernel_reset: 112,535 gates
  private_kernel_tail: 88,987 gates
  hiding_kernel: 38,069 gates

⏳ Executing verify_comm (small) on-chain...
[12:17:54.297] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 1733.4174590000039ms
[12:17:54.575] INFO: embedded-wallet:pxe:service Registered account 0x2b28f6497b4c914442d0aaa221d5907eac1f1f34d427838dae9ede49e1c57458
[12:17:57.551] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 1909.299583ms
[12:17:57.551] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
[12:18:01.350] INFO: embedded-wallet:pxe:prover Generated ClientIVC proof {"eventName":"client-ivc-proof-generation","duration":3799.228124999994,"proofSize":4719}
[12:18:02.420] INFO: embedded-wallet Sent transaction 0x166c05ff6fd2c1f96fcbba6640a08d9b545f46664cafb3e2704d9ce757359c63

✅ Transaction confirmed!
   Status:       checkpointed
   Block number: 57051
   Duration:     68.2s
✨  Done in 152.66s.
```

```
# yarn tsx devnet-verify-comm-large.ts 
yarn run v1.22.22
$ xx/zktls-verification-noir/example/js_test/node_modules/.bin/tsx devnet-verify-comm-large.ts
======================================================================
TEST 1: verify_comm — BusinessProgram (MAX_COMMS=65)
======================================================================
[12:24:33.598] INFO: kv-store:lmdb-v2 Starting data store with maxReaders 16
🔑 Secret key: 0x11c65c679a49736435be1e0dbdd07e45adb69ae3a56800bf7338f9c88682161e
🧂 Salt: 0x15ca392bb8563aa118198b92f46a3d2a3ab4f0abbdd4afefdbd91ae6e611f1ea
⚠️  Save these if you want to reuse this account!
[12:24:33.913] INFO: embedded-wallet:pxe:service Started PXE connected to chain 11155111 version 615022430
[12:24:33.913] INFO: kv-store:lmdb-v2 Starting data store with maxReaders 16
Account address: 0x2fd95a3de60455c7cc7aee785109d5442deecd6548d96daf38e20439d122084e
[12:24:34.089] INFO: embedded-wallet:pxe:service Added contract SchnorrAccount at 0x2fd95a3de60455c7cc7aee785109d5442deecd6548d96daf38e20439d122084e with class 0x0a167ca249952af052a802e0520f2ab08870fa28619c00a95e9e1bf3caf0fb2b
[12:24:34.092] INFO: embedded-wallet:pxe:service Registered account 0x2fd95a3de60455c7cc7aee785109d5442deecd6548d96daf38e20439d122084e
[12:24:34.094] INFO: embedded-wallet:wallet:db Account stored in database
⏳ Deploying account on-chain (~2-5 min)...
[12:24:34.258] INFO: embedded-wallet:pxe:service Added contract SponsoredFPC at 0x09a4df73aa47f82531a038d1d51abfc85b27665c4b7ca751e2d4fa9f19caffb2 with class 0x2a70a2847b3af93b7a60f922c6e8ddda9066fa38ee9713ade9104d2556bf5e1a
[12:24:39.017] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 2261.042125ms
[12:24:39.017] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
[12:24:42.042] INFO: embedded-wallet:pxe:prover Generated ClientIVC proof {"eventName":"client-ivc-proof-generation","duration":3024.520917,"proofSize":3216}
[12:24:43.116] INFO: embedded-wallet Sent transaction 0x2242dc82f3a5a3e711e6d77ee028ece0b29c03c55b638f503aca2252fe79f6b5
✅ Account deployed!

Commitments in test data: 65

Deploying BusinessProgram contract...
[12:25:38.820] INFO: embedded-wallet:pxe:service Added contract BusinessProgram at 0x074fff41dd32066da0c58530a26473f5e5049c440145dd634dfa47254042d892 with class 0x23eaaedf245cadfd429ff7ad736270af84a6e8944fbb51f29c19d3225ed68df0
[12:25:39.043] INFO: embedded-wallet:pxe:service Registered account 0x2fd95a3de60455c7cc7aee785109d5442deecd6548d96daf38e20439d122084e
[12:25:43.135] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 1917.5332499999931ms
[12:25:43.135] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
[12:25:45.873] INFO: embedded-wallet:pxe:prover Generated ClientIVC proof {"eventName":"client-ivc-proof-generation","duration":2737.7833750000136,"proofSize":4719}
[12:25:46.677] INFO: embedded-wallet Sent transaction 0x0ba39d2069a478aaf5dbc6b2fe42d85c6f0121869ca6d56f162cde15514dbc73
Contract deployed at: 0x074fff41dd32066da0c58530a26473f5e5049c440145dd634dfa47254042d892

Profiling verify_comm...
[12:26:14.901] INFO: embedded-wallet:pxe:service Registered account 0x2fd95a3de60455c7cc7aee785109d5442deecd6548d96daf38e20439d122084e
[12:26:15.102] INFO: embedded-wallet:pxe:service Profiling transaction execution request to 0x9d57a239 at 0x2fd95a3de60455c7cc7aee785109d5442deecd6548d96daf38e20439d122084e {"origin":{"xCoord":{"asBigInt":"21642732522421997932212029138101695497834397921761466707249788918865303046222"}},"functionSelector":{"value":2639766073},"simulatePublic":false,"chainId":{"asBigInt":"11155111"},"version":{"asBigInt":"615022430"},"authWitnesses":[{"asBigInt":"5470205988431374559083547306667006465117718457666708974781048540142527711167"}]}
  SchnorrAccount:entrypoint: 54,352 gates
  private_kernel_init: 46,811 gates
  BusinessProgram:verify_comm: 3,907,426 gates
  private_kernel_inner: 101,237 gates
  private_kernel_reset: 112,535 gates
  private_kernel_tail: 88,987 gates
  hiding_kernel: 38,069 gates

⏳ Executing verify_comm on-chain...
[12:26:23.078] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 3724.148583000002ms
[12:26:23.280] INFO: embedded-wallet:pxe:service Registered account 0x2fd95a3de60455c7cc7aee785109d5442deecd6548d96daf38e20439d122084e
[12:26:28.393] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 1984.0232499999984ms
[12:26:28.393] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
file:///xx/zktls-verification-noir/example/js_test/node_modules/@aztec/bb.js/dest/node/cbind/generated/async.js:103
                throw new BBApiException(result.message || 'Unknown error from barretenberg');
                      ^

BBApiException: Assertion failed: (new_virtual_size >= virtual_size_)
  Left   : 2097152
  Right  : 4194304
    at <anonymous> (/xx/zktls-verification-noir/example/js_test/node_modules/@aztec/bb.js/src/cbind/generated/async.ts:112:15)
    at process.processTicksAndRejections (node:internal/process/task_queues:103:5)

Node.js v24.13.0
error Command failed with exit code 1.
info Visit https://yarnpkg.com/en/docs/cli/run for documentation about this command.
```

```
# elena$ yarn tsx devnet-verify-hash.ts 
yarn run v1.22.22
$ /xx/zktls-verification-noir/example/js_test/node_modules/.bin/tsx devnet-verify-hash.ts
======================================================================
TEST 2: verify_hash — BusinessProgram (Poseidon2 hashing)
======================================================================
[12:27:50.616] INFO: kv-store:lmdb-v2 Starting data store with maxReaders 16
🔑 Secret key: 0x031b2a11ae1285af3cd0fb5c016f9661ebb61da0200942eec1fedacdc1db3da5
🧂 Salt: 0x01b7f75c9eaf15edaebca2df443c902a4940506b1a1297b53a653b3392bc3e31
⚠️  Save these if you want to reuse this account!
[12:27:50.937] INFO: embedded-wallet:pxe:service Started PXE connected to chain 11155111 version 615022430
[12:27:50.937] INFO: kv-store:lmdb-v2 Starting data store with maxReaders 16
Account address: 0x0a410a88be1f32549bed6a5f097e524d051fb30aaf350bd645034e41739a901c
[12:27:51.224] INFO: embedded-wallet:pxe:service Added contract SchnorrAccount at 0x0a410a88be1f32549bed6a5f097e524d051fb30aaf350bd645034e41739a901c with class 0x0a167ca249952af052a802e0520f2ab08870fa28619c00a95e9e1bf3caf0fb2b
[12:27:51.228] INFO: embedded-wallet:pxe:service Registered account 0x0a410a88be1f32549bed6a5f097e524d051fb30aaf350bd645034e41739a901c
[12:27:51.230] INFO: embedded-wallet:wallet:db Account stored in database
⏳ Deploying account on-chain (~2-5 min)...
[12:27:51.427] INFO: embedded-wallet:pxe:service Added contract SponsoredFPC at 0x09a4df73aa47f82531a038d1d51abfc85b27665c4b7ca751e2d4fa9f19caffb2 with class 0x2a70a2847b3af93b7a60f922c6e8ddda9066fa38ee9713ade9104d2556bf5e1a
[12:27:56.004] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 2144.399459ms
[12:27:56.004] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
[12:27:59.035] INFO: embedded-wallet:pxe:prover Generated ClientIVC proof {"eventName":"client-ivc-proof-generation","duration":3030.777333,"proofSize":3216}
[12:27:59.926] INFO: embedded-wallet Sent transaction 0x1f388937de4e33cf20c39ff28b370dcd22fe9d746fd396ccb547bad54b5492cc
✅ Account deployed!

Deploying BusinessProgram contract...
[12:28:38.838] INFO: embedded-wallet:pxe:service Added contract BusinessProgram at 0x1cc0537984d1c52ae3f291be3e3c31084084a508a5e42b55b686d17644ba6f59 with class 0x23eaaedf245cadfd429ff7ad736270af84a6e8944fbb51f29c19d3225ed68df0
[12:28:39.068] INFO: embedded-wallet:pxe:service Registered account 0x0a410a88be1f32549bed6a5f097e524d051fb30aaf350bd645034e41739a901c
[12:28:43.348] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 1925.222332999998ms
[12:28:43.348] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
[12:28:46.054] INFO: embedded-wallet:pxe:prover Generated ClientIVC proof {"eventName":"client-ivc-proof-generation","duration":2705.994541,"proofSize":4719}
[12:28:46.928] INFO: embedded-wallet Sent transaction 0x0fa7c94a08266a0ed8179a72a133a7f909e24bc2f7c50ac93a9e522e65a5c944
Contract deployed at: 0x1cc0537984d1c52ae3f291be3e3c31084084a508a5e42b55b686d17644ba6f59

Profiling verify_hash...
[12:29:37.822] INFO: embedded-wallet:pxe:service Registered account 0x0a410a88be1f32549bed6a5f097e524d051fb30aaf350bd645034e41739a901c
[12:29:38.050] INFO: embedded-wallet:pxe:service Profiling transaction execution request to 0x9d57a239 at 0x0a410a88be1f32549bed6a5f097e524d051fb30aaf350bd645034e41739a901c {"origin":{"xCoord":{"asBigInt":"4638046249081642458628234732900687725853499620897545102263471689303427026972"}},"functionSelector":{"value":2639766073},"simulatePublic":false,"chainId":{"asBigInt":"11155111"},"version":{"asBigInt":"615022430"},"authWitnesses":[{"asBigInt":"3103338491624980501075639122345350174470635756616182035257697047656963564887"}]}
  SchnorrAccount:entrypoint: 54,352 gates
  private_kernel_init: 46,811 gates
  BusinessProgram:verify_hash: 2,509,592 gates
  private_kernel_inner: 101,237 gates
  private_kernel_reset: 112,535 gates
  private_kernel_tail: 88,987 gates
  hiding_kernel: 38,069 gates

⏳ Executing verify_hash on-chain...
[12:29:44.807] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 2943.2390000000014ms
[12:29:45.010] INFO: embedded-wallet:pxe:service Registered account 0x0a410a88be1f32549bed6a5f097e524d051fb30aaf350bd645034e41739a901c
[12:29:49.813] INFO: pxe:private-kernel-execution-prover Private kernel witness generation took 2048.9825830000045ms
[12:29:49.813] INFO: embedded-wallet:pxe:prover Generating ClientIVC proof...
file:///xx/zktls-verification-noir/example/js_test/node_modules/@aztec/bb.js/dest/node/cbind/generated/async.js:103
                throw new BBApiException(result.message || 'Unknown error from barretenberg');
                      ^

BBApiException: Assertion failed: (new_virtual_size >= virtual_size_)
  Left   : 2097152
  Right  : 4194304
    at <anonymous> (/xx/zktls-verification-noir/example/js_test/node_modules/@aztec/bb.js/src/cbind/generated/async.ts:112:15)
    at process.processTicksAndRejections (node:internal/process/task_queues:103:5)

Node.js v24.13.0
error Command failed with exit code 1.
info Visit https://yarnpkg.com/en/docs/cli/run for documentation about this command.
```