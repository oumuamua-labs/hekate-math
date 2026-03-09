// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <zeek@tuta.com>
// Copyright (C) 2026 Oumuamua Labs. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

// === 8 BIT CONSTANTS ===
// Generator 8:
// Block8(27)
const FLAT_TO_TOWER_8: [u8; 8] = [0x01, 0x1b, 0x5e, 0xb3, 0xe4, 0x94, 0xe8, 0x20];

const TOWER_TO_FLAT_8: [u8; 8] = [0x01, 0xe4, 0x4d, 0x1d, 0xfa, 0x80, 0x4a, 0x97];

// === 16 BIT CONSTANTS ===
// Generator 16:
// Block16(4394)
const FLAT_TO_TOWER_16: [u16; 16] = [
    0x0001, 0x112a, 0x1a45, 0x510b, 0x5faf, 0x0c28, 0xb194, 0x148c, 0xe51c, 0xf7cf, 0x50c2, 0x896a,
    0xec15, 0x9608, 0x0bb1, 0xdadd,
];

const TOWER_TO_FLAT_16: [u16; 16] = [
    0x0001, 0xe02c, 0xd908, 0x7e8d, 0x50f3, 0xd8c3, 0x7fdb, 0x2887, 0x2dd8, 0x8f3a, 0xe43a, 0x4254,
    0x6bb8, 0xb969, 0xd8c8, 0x5e35,
];

// === 32 BIT CONSTANTS ===
// Generator 32:
// Block32(4030672443)
const FLAT_TO_TOWER_32: [u32; 32] = [
    0x00000001, 0xf03f2e3b, 0x463a215e, 0x5196f37d, 0xbf3906b0, 0xf6d11f50, 0xb144ca50, 0xb09fe505,
    0xb8dc201f, 0x0c73831e, 0x5285ebaf, 0x0e7151e2, 0xec3f50b9, 0xa8fd07be, 0xed706a15, 0x19b8cb86,
    0xad06d078, 0xfb982c9e, 0x5037cbed, 0xb8d85e23, 0xb4fa1b2c, 0xb0dd8490, 0x54b34ee7, 0x14e7f706,
    0x0d99add7, 0x8b5bb46a, 0xb6268855, 0x0dc48504, 0x0c472027, 0x839ef632, 0x5a18ecdd, 0xe62bcc14,
];

const TOWER_TO_FLAT_32: [u32; 32] = [
    0x00000001, 0x40a46afa, 0xc4652dfc, 0x7ecda763, 0x9c8bad52, 0x3ea34653, 0x049aaa6a, 0x4c7d73fb,
    0x9c34a3a5, 0xbaecc5fa, 0xc431b802, 0x6b634bc7, 0xfb7b01d1, 0xe34bd431, 0x7f17607e, 0xae247c83,
    0x3a2996e2, 0xea139938, 0x6a11e33f, 0x4c8caca7, 0xf79c25b2, 0x3adf4603, 0xfec87d06, 0xaaf119c9,
    0x09a689ae, 0x2ad0f3e1, 0x08ec504b, 0x052614cd, 0x738ace24, 0xb19fe981, 0x54826549, 0xc7c7a58a,
];

// === 64 BIT CONSTANTS ===
// Generator 64:
// Block64(388695496543108587)
const FLAT_TO_TOWER_64: [u64; 64] = [
    0x0000000000000001,
    0x0564ec7ea53efdeb,
    0x11c148c5b239a785,
    0xe48e279bf9ec1ceb,
    0x1a5dd34b57d10be0,
    0x5e52d985a5793126,
    0x4dad66a9903b076c,
    0x19775fd5ffb57ea4,
    0x5ff493ef0048569e,
    0xaacf2e313017a758,
    0xe42be3223c7db919,
    0x130da328c0280682,
    0xfad54450a08e1ae8,
    0x5fc84f01bcb80968,
    0x5a7c49d5b984d00d,
    0xab68f92571a4fe2a,
    0xe5e91f2901297d4d,
    0x4df872cb78b471a9,
    0xb2d56ce6d32aa514,
    0xe7cb0f330827dae9,
    0x4d4ab849ce91dafb,
    0x476c4f8be23042b8,
    0x1ebc74c1e7b24c52,
    0xb12ba8b263e6bfd7,
    0x027b02e25027ae04,
    0xb968a5a32d7af90e,
    0xe5cee9f99c017979,
    0xb111e1808ad971eb,
    0xf4258f8352c455a5,
    0x0b516c1a7c39cc1a,
    0xb316602062d4dfc2,
    0xbe371214aa5186e6,
    0x4c5f18962762d231,
    0xa4db4fd6645add40,
    0xfa74a8e834e73862,
    0x11f7ebe4237a0915,
    0xe91f7ed8c186da65,
    0xa24ca22e8d62f1df,
    0x48b7872f4e11028d,
    0x17a6060fd5ed3c61,
    0xfa9df9544d203ab5,
    0xed0fd9a8debe6761,
    0xbebd9e1a128df305,
    0xa326af2174fa80c0,
    0x4f9ea9d414948043,
    0xb1e9f8bb3b42f912,
    0xecad4ef3703177f5,
    0xf700d95300bac1c2,
    0x041989726fbe4fa8,
    0x01e38b8baef9142d,
    0xacdb8579ed778922,
    0xed2e4df803eb4f4b,
    0x4c26f312013fc230,
    0x08f95dfea6ac592c,
    0xec9e9ec4a9c6ee9a,
    0xa856960738631da1,
    0x56536fa09cc4e831,
    0x575b51d64160bdd3,
    0x45c9a7bb11136d24,
    0xf4cbceec52274781,
    0xe80bb87f2fede9a3,
    0x87d06b5c36f8911c,
    0xb9a809ee5b09be01,
    0x38869209014ec5d2,
];

const TOWER_TO_FLAT_64: [u64; 64] = [
    0x0000000000000001,
    0x0da5664f2db6075d,
    0x033ce8beddc8a656,
    0xe6cc7aa05b65d0c8,
    0x512620375ed2a108,
    0x534816ee5cdcc0d8,
    0x0c9e636090aafc01,
    0xfe579258a329cb4d,
    0xb049a462e02d58aa,
    0x471bb5002ec092ab,
    0x4bc4dfe954868f13,
    0x4e89c74791575c38,
    0xab57898bde25db1e,
    0xbc5c2a471b0875ed,
    0xb3387c6656a2f210,
    0xba2dff38f64de351,
    0x536ab5fca8b53582,
    0xed2cba414243fd2c,
    0xb142844b12b1575b,
    0xaa89d5a08706469f,
    0xadca3c4e6fcf14e3,
    0x1fe977f5c76750c0,
    0x06740b5a95247b68,
    0xe3812b124fd5f994,
    0x076c2acc74350d9c,
    0x005271da313e9524,
    0xa570e110044caffd,
    0xe0f3cef49e0127e1,
    0x04d3c1b703a85818,
    0xaf1910a03a85223e,
    0xbcfaec00a85e5053,
    0xeca8ada2271c1ce0,
    0xff4fb7b1cc448074,
    0xf841cfef9ac08d9f,
    0xac2d4dbe104d46f3,
    0xb47072448e3e2552,
    0xa4983ae6ab26a5bc,
    0xed11dc049642c72b,
    0x42978cb4d19793a4,
    0xbde51e9b4cf7f3f3,
    0x06f43540551e8549,
    0x576b0af612a060a9,
    0xb65483945a910b77,
    0xbb15de8f65b563ca,
    0xb5a0655f15568602,
    0xb037fa638307a8ea,
    0x5eef64e6ff16d2fa,
    0xe059c55aecc12aef,
    0xad2590e9ac9c1756,
    0x1cc0124a000ae588,
    0x58f034dba58d3191,
    0x064d5bad24d113b3,
    0x566fa696f4039749,
    0xbd8363b5f7062435,
    0xf7243d4773125c79,
    0x1076ffa7b6f9e739,
    0x110029157f2e6e4a,
    0xf9f6eb833558f236,
    0xaf0e6e13520d209d,
    0x40cc13417c0c7e66,
    0x59e1eecf6c48afd0,
    0x2febce17c8314609,
    0xfca4f3efa0a3c706,
    0xca97a1917a714ea7,
];

// === 128 BIT CONSTANTS ===
// Generator 128:
// Block128(13209536707042023373099634195482672186)
const FLAT_TO_TOWER_128: [u128; 128] = [
    0x00000000000000000000000000000001,
    0x09f010715928b997f12f19f0e44dfc3a,
    0x41bec9a2ecd47653d743b220f2861bd1,
    0xe4da4358f0d6c557e88b83c65b283c5e,
    0xaa25207673a8d693077209e0ff8844f7,
    0xa1342ea818b4a65b0e716a93c559ea73,
    0x4d0d76389d6a0fd191e033a553044102,
    0xa62daee91a27032c081f17e9de64961a,
    0xb2cc3536e06b98b9b04be965f99f1b87,
    0x5ed20f338613ce895640081404754de3,
    0xf7aeedbf2067fe2892fa8c670eb1f826,
    0x0dc9ca1c345aa24c9032b5182499de45,
    0xfa23b69db97ec9c85aa5d0de64fc0b66,
    0x1f56f8ef37d2f2f64118e38ee6ccc604,
    0xe262098ebf5815607da4e6f690e299e9,
    0xe1a9bebe280f69b28e4313ac080c2e94,
    0xe9453afb521bc0938f781867f65628bb,
    0x5e8845e9bcdda10de1bb4b7fce6b6032,
    0xe4b11b5a386b0d2df09bb6093b45a8ac,
    0xaed39c83d812667861abac55b7e60732,
    0x532c7553b9a1940780f061ee04c8b744,
    0x40fe850efe58bee671cd0811da6362c8,
    0x51be91c16d42229af616296614ef2b6d,
    0x51803487324f4d37c6043a57ccdb742a,
    0x0229ee1a12ff61031a3ad708013504f5,
    0x04b37ea79c752841a469b9779326a50e,
    0x4ea722a8b64df0e7fa7d78a5cf05d9b5,
    0xf86c81f79701cfedabe764c4a4cb5019,
    0x591662d34a563e43ebfa77059fdfa173,
    0x4adbc38c53b758b18447472d2e66cca0,
    0x5cc2ff517685c2669a8327c523838e26,
    0x0ada947caa4b81674b2b0a5d20b10584,
    0x1c1748457440374e6c914308e423379b,
    0xe9787d393da8acec6d4ad0a153c63ef8,
    0xe4455dd04a194cc92e86963fde0f9b24,
    0x45936b7a8c4c697f33c433ed9ec585b3,
    0x4d8f6d159d175558a75cb528f569b492,
    0x0b2f79cbce44cf3468e889a058ec5acc,
    0xa2a88ab110922360ef63813e310f7ce7,
    0x07a000f23a5a2b6fa90ffda7eb8e9303,
    0xb56d93b39ef7ec272fef4b1dc15f28cb,
    0xa92bc3f9432723e5a79b8fae353a43c7,
    0xabae2bee613a8c52a5656042bc78f698,
    0x1c0ddba4940f0d14459b8f21b494a4ad,
    0xb168fefee8fe11ea88db6be91fb4287d,
    0x10ba30591f2db9820080d82b78cffea6,
    0xb14b15bebd24637c80a23ba40b878273,
    0x5f9ea33ae54e7a6971ae18a2f6bf66fb,
    0x04adf5cfe2e59bcf2cd7010b08fcd098,
    0x0682c3ae014ecad5975a55bf690cfa83,
    0x10de20c95d1d8f979f4ce1c00c581234,
    0xfe1f93419b8a1303adec13fea0a78b2b,
    0xff31c01c8f0f2cf81a0d108d0159b19b,
    0x0e3d569ed877caddf2f9bfa0b32176d1,
    0x065755c6a76c9e69413d59a8cc24b7ce,
    0x1f4fd572502974d6a1a50866c54710ab,
    0xf1060a079dee76fe38b51958be513319,
    0xf22f64e06ca1bf577af0a50733be8e3e,
    0xef8b008fd136e115b8649525fc5a5365,
    0xa923880769bf1b7a3d74291d14076d60,
    0xe02a3b2af6629de45f4537ce4309ad33,
    0x18720639e2c18039a4f91092c5c99557,
    0x443653c40dda85df41990924c9736516,
    0xe19a5221bdb4eafd52475905cafa50fa,
    0x4bad347970faab25abc595187fe9fce8,
    0x0de06d1da90ec75f879d21016e0dc522,
    0x1c315a5af137db31b625ca4f9b382cdc,
    0xf0aeadfadb8dcfcb9e4e14a3e252fa0e,
    0x4dd9fcc113db7dade9e50ccb6e74aa79,
    0x1bb6eefcb9485b42237ac9d48e9573cd,
    0xba2e9fef553b008589086bcef6773bad,
    0x41b1fcc2b04c82fad18059da2d355f75,
    0xfabdae95c9243597d941c327bc73e5f1,
    0xe8c96e992df83b4f05a92edd98831951,
    0x45411dcb60264159b79c3c0091fd4b9c,
    0xe716afcf999ff36ef81bd69cd13a437b,
    0xf2df09fd6566b94c9fe98e9ec976f2cf,
    0xf8ce10858cf8a16c8f95b99cd56bcae8,
    0x1560221ff064c2336083a4c49793bd68,
    0x09728e2f5ca81ad224e206c7aad218cf,
    0xfc24da7257ea3d875bd1592bc029d7dd,
    0x0b153fa32cf4a7445be281d0d33c888a,
    0xb73864cbc2a979aa6587ab27055e3c57,
    0x008b6c9f4739586adf0c28552b99e3a9,
    0xb33382e3f9592467a702487947e40518,
    0x00e6d2b819e3c385ff20a525a343e6f8,
    0x4bf2a50ee71be7f8b39db1df48c03c79,
    0x5e88a288a0d02f951b6d8de9289a9c99,
    0xec03f64f33907902aab5b1f09678464d,
    0xa754657ec18320d3c1096357c99674bf,
    0x1be4a5f0d209ff0230083bedabc34a2a,
    0x580b84291fcf92cd9cc090de5a3fffc2,
    0xec6a61c90b2086d80f343242a876353f,
    0x408a6d7ed5b35fc362a8d3ddf857463e,
    0xe56aa3703991047ced4ea6cff67e4cef,
    0x5bd6f3e7d9fa6a2158a5494c19477160,
    0x1091dcf0259da137f7ed642be414f3ae,
    0xe62065fa90898b8d635826de832b0c36,
    0x1428f549aa7ec2fb9b74a27940b943b9,
    0xb64f1cb32b26776cc44b7a298dc38230,
    0x1b331b3c1a756449b7eb766f8eced387,
    0x18ef3871793c88c1bc95c6825db7fb98,
    0x1238b3c371d2180be3854055ec810821,
    0x5c8f4f9a7dc5056f9d23389bfc7811f0,
    0x13200b1f430afc578cc8db499cd01f19,
    0xaf327d4f320465f9079a1c76853b1291,
    0x544809fd6e6805a4615925617c68ada2,
    0xbe2f12f6c24dbb1587e2c72298ac2001,
    0x141341f3b2ebcbd7837322cb7c0df221,
    0xe6f0553319e4537d8b1c1a804460b301,
    0x4efdaa991bbaea95c2731cdb175a6fab,
    0xa8a3a8e02f327742bc42e0ae9d4f16ba,
    0x472c8b0c5448beb2851abb4615373091,
    0xfc95ec89481dbb404c14a1c5d7e0a8e5,
    0x42a1a87e6dd227cf6c5309ad41d2cb8b,
    0x44b0247829961dd27c8367e4f4df4a3e,
    0x08c4e8822cb92e2977be9e46fdaec7ee,
    0xfa55775d45895d2c8c2d6fadb7474945,
    0xb778521d2dd95693f778e8824c07ca66,
    0x18aaa549be649ed7de3909caaf3c62c7,
    0x5d7d5e7c12d95d8333bdd2414da1b182,
    0x859420d47e6e6105721bf9330dc33b94,
    0x5b4de2bdbacdf8312f7660fbda25528a,
    0xb09aff3b8e888b1ac665190a98e019ac,
    0xbbe91b801933b7aa5862ad8516e2f206,
    0x1fce8a0b7fca424ff434e156b0ce5256,
    0x5cb0303ee30009e2f000cf1463469995,
    0x2b646d648858b8a7ac285c086925fa5e,
];

const TOWER_TO_FLAT_128: [u128; 128] = [
    0x00000000000000000000000000000001,
    0xb61257cfad572414ed09ef16e07b94c6,
    0x053d8555a9979a1ca13fe8ac5560ce0d,
    0xf72dd6ca714abd6e6afd8694e8dda26f,
    0x4cf4b7439cbfbb84ec7759ca3488aee1,
    0x93252331bf042b11512625b1f09fa87e,
    0x35ad604f7d51d2c6bfcf02ae363946a8,
    0x049b075c0f15ad1e11f9bedcdd1861f4,
    0x1037b7b8bf8d11f62439d98237728906,
    0xe3d708391d5510b27ac1154f2d3707c0,
    0xbf6d6ab62fc6070cbb97443e5a2e7db9,
    0xeab4ae445de46b1c23616fcc33890742,
    0x599a42c078947aa7d721c5f96eb621cc,
    0xdfa329d3edd3748888f56deb5fc00fc9,
    0x011541c87c40511af3a58717783a8037,
    0xba2f3349d62794f645fe173965392c8d,
    0x59dd36a768d8b329c4196a58135c73b3,
    0x8304eaf5704060640d92112f365f6637,
    0x78e57a1658d1b35eabe276661d275d8f,
    0x253c27ed89624aa907532e029d3b4647,
    0x542df9657a1c80e1493acad20eadcdb3,
    0x6dfe3252f95d05184f075c99b31e60b6,
    0x1cf43db29d835145e207514a03d76668,
    0x014b7622faf0234c6d100eb3d55527b1,
    0x8bc927c8bf2463453552ad65a20a711b,
    0xc68f7b310858b1ae31db24bbebbe5f9f,
    0xae715138485afc2b2adaa101cc89fc78,
    0x45e9db200ee5b62ad0fd482a10b4bd98,
    0x08d50e6d1e35ef848e52ba0073410dcc,
    0x35bc05354757b7336c78c9ddece4c05f,
    0x9ebccfbde0c449691a22c6ef1c7cf690,
    0x6c34842a63f862a11bd82fa693ebf16f,
    0x24bb382dfc84d33f3eb915d4cc6c752e,
    0xaaff995a1a355389cdbddf0dc5ceb9ea,
    0xc392c17154e2b62cef17ec0d23105505,
    0x9a4479b077efe49b7372376d83d691b8,
    0xb3786571fdbdfeec02755958f8ed4f8a,
    0xaa1c2217d259cd80d56639054dce2978,
    0xce65f3a45c9d3d3dfe90cd77093286d7,
    0xca2bda6646cb18d788151ad0e5e8fe65,
    0x3545184b32c7601efdf7f8c3c41e7aed,
    0x6d680f479027a3b7ccb252d043ba35bf,
    0x7105ef8110755f5f8bd1462a55d6a86a,
    0xf625d48193e265c6ea94e208e9ab06be,
    0x9a850fc8edf304f9c0ce15aa1830fde6,
    0xba1e387854f4696e56e54dde12672779,
    0xca96bd379ec798681cb42b0efccec845,
    0x49b37b601953d0ca44eaaabb7aa3f44b,
    0xa2fb5dad65c78028384cc7dae2353695,
    0x38357b6a84ff599949f6cc9aecbe70e0,
    0xeee01465e725c21c70895235535ca4f4,
    0x1dcaa18111cd5236c65b54fbe910731e,
    0x92f0893e125f9a3deb3b6d6bfff4d35e,
    0x2073bf1ac106648558f89261d4cdbf38,
    0x39c368e5450e4b63122926c55392928c,
    0xa633e0d0b82941d9ffc78f8589d45b9a,
    0x508dddcb926d8cf6e38d9ca44ba8a645,
    0xabde87ca06685628df5b7834d2b045ff,
    0x9717263ded33a5dfdd3bbda3fdd9ed5d,
    0x58faf4b3bc29e748bbf0fdefb8a1fa11,
    0xe2c889c4ac3a441929e2a9dd519e839b,
    0xbb51a8eadbe66a2a1b8999a12edd9b1d,
    0x70345a2f9e1b68d2a8e033eb0720cd18,
    0x05d7c97ecbbebc818fc2e11fc2ac39af,
    0x18eb63fbf402271f3da89ebb3d323232,
    0x7145d8b46d0e012add29c73b8c362fc8,
    0xbf09b5e18d48eabe8aa5cfa7c67c5305,
    0x6c71bf89babb516078787d7db4d800c8,
    0x553fe5ac9f0e35778920b150ced0d1f0,
    0x399e02761bf42ae78ae7431171857fc8,
    0x9f2b10c220ed833788dfafd5db3eb44b,
    0x838b526016476e98841276810b47c556,
    0x210bcaab65ff042add17c7a712bc6011,
    0xeb311496de5aaf2c653cbe602286191a,
    0x017f1263a652ceba10c320eb48c9b78c,
    0xe67565fb8f1f9721ac340c0fd7bc60cf,
    0xc3371abe9bac8a8efbbe1dd4f102d4bd,
    0x7c58b966394afb0205ff1d4aaf2e8fd9,
    0x9eeab9b67230d60ccc3f5951e4c98e73,
    0xc73f81aec0650a60103a078bcaac73a8,
    0x8263a2adb1b6dd128be35f097470dbf9,
    0xae65e03d2c89aa15b15b0dfa5c17961b,
    0x5dc6342b34e3f321583f1ff695674827,
    0x19a73cc3df1f29e8b94dbdea724df9e6,
    0x876990b13492ad5989c8c0c30391ef55,
    0xbaddea51b65ee5c3bec2ded141025e1f,
    0x1c22ae02c776870f8334ecc656051766,
    0x11118947e13c827f1a655a6796dc971a,
    0x4da214c4ab1efc17ae509d043dae2bc4,
    0xb660dcee121a37a0ac5d8fbb11e30d57,
    0xb74249b487598ca926a6381626af1de4,
    0x0014cd381592425d4b9f8d004fc9b3ff,
    0xc769c172db1063d709924de115266aeb,
    0x3528c3d1b73f75b8a96c30b68d864b61,
    0xf68e897b7cb982d98c7081032baa3442,
    0xdb27a419dbabc6755ae635a86e0e95f8,
    0xb27c81284d5a94af202894541f86c045,
    0xe2849dc3f088066bf0490eec9fd01071,
    0xe3bc77dc19848937b1584228fc217fb3,
    0x1cfc5004d3e9152cb4a4cd181b5bb59a,
    0x9725230891dea8e4802c2aff92570190,
    0x931476270cec2238212e3523e7d0a1df,
    0xa62ed819b5358980134193aba268a13d,
    0x495b6b7de947e5d73d204be7074d4c7c,
    0x201bd73382b3a79e720825e21a336bcd,
    0x514be400054f1517466c87533db61605,
    0xee75d64af79d8382b1fdb33b03f50c79,
    0xa62ff6334e941b3627746f5ac51d7966,
    0x4c7b439893f55cb3943cbdb0dd900cf9,
    0x83aebbd750f7c6f4ab0256516f98a92d,
    0x45499d598f0f80c7d4c00b6f832324c2,
    0xfea52db383fbce582ec06bdc0673a6b8,
    0x9e8ac304150a5f8b5101c691c92afc8b,
    0x49c92409c5aa04066badee420edb7758,
    0x31ce326d52388bd0e5b8d924c70b2d08,
    0xe344aaec4df8d8c0845c00a2f5c7cf37,
    0x58884a7ce9b1b1dd3776b76b3252f71a,
    0x58503c5590f08c6ecefd6a35a65818ec,
    0xf22ca5192b74dce987573007fd27a4f6,
    0xb2e5c95a6fbe6565c8a42b15b561ff62,
    0xcea23f63670107487795bc0fc55ca26b,
    0x05a7ed5f12f1aec20f84274ad639955f,
    0x59dd0c344fb6785309225ca5a67f9c3f,
    0x449376e4ccf33d83c11240cadb3dce7a,
    0xd699d89af7200ca18fcda15e21288196,
    0x66340c45203fe3685d08f8c248334a81,
    0xca0381d0fb098147456b3d6d30001dbe,
    0x6eb6e127845ac2c1e03b8e06c43e7d5f,
];

// ==========================================
// 1. MATRIX MULTIPLICATION (PURE XOR)
// ==========================================

macro_rules! impl_apply {
    ($func:ident, $type:ty, $size:expr) => {
        fn $func(val: $type, mat: &[$type; $size]) -> $type {
            let mut res: $type = 0;
            for i in 0..$size {
                if (val >> i) & (1 as $type) != 0 {
                    res ^= mat[i];
                }
            }

            res
        }
    };
}

impl_apply!(apply_8, u8, 8);
impl_apply!(apply_16, u16, 16);
impl_apply!(apply_32, u32, 32);
impl_apply!(apply_64, u64, 64);
impl_apply!(apply_128, u128, 128);

// ==========================================
// 2. LOOKUP TABLE GENERATORS
// ==========================================

macro_rules! impl_write_table {
    ($func_name:ident, $type:ty, $windows:expr, $width:expr) => {
        fn $func_name(file: &mut File, name: &str, base_matrix: &[$type; $windows * 8]) {
            writeln!(
                file,
                "pub const {}: [{}; {}] = [",
                name,
                stringify!($type),
                $windows * 256
            )
            .unwrap();

            for w in 0..$windows {
                for val in 0..=255u8 {
                    let mut res = 0 as $type;
                    let window = &base_matrix[(w * 8)..((w + 1) * 8)];

                    for (bit, &col) in window.iter().enumerate() {
                        if (val >> bit) & 1 == 1 {
                            res ^= col;
                        }
                    }

                    writeln!(file, "    0x{:0width$x},", res, width = $width).unwrap();
                }
            }

            writeln!(file, "];\n").unwrap();
        }
    };
}

impl_write_table!(write_table_8, u8, 1, 2);
impl_write_table!(write_table_16, u16, 2, 4);
impl_write_table!(write_table_32, u32, 4, 8);
impl_write_table!(write_table_64, u64, 8, 16);
impl_write_table!(write_table_128, u128, 16, 32);

// ==========================================
// 3. TOWER BIT MASKS GENERATORS
// ==========================================

macro_rules! impl_write_masks {
    ($func_name:ident, $type:ty, $bits:expr, $apply_flat_to_tower:ident, $width:expr) => {
        fn $func_name(file: &mut File, name: &str, flat_to_tower_basis: &[$type; $bits]) {
            let mut masks = [0 as $type; $bits];
            for j in 0..$bits {
                let x_flat = (1 as $type) << j;
                let y_tower = $apply_flat_to_tower(x_flat, flat_to_tower_basis);

                for k in 0..$bits {
                    if (y_tower >> k) & 1 == 1 {
                        masks[k] |= x_flat;
                    }
                }
            }

            writeln!(
                file,
                "pub const {}: [{}; {}] = [",
                name,
                stringify!($type),
                $bits
            )
            .unwrap();

            for (k, m) in masks.iter().enumerate() {
                writeln!(file, "    0x{:0width$x}, // k = {}", m, k, width = $width).unwrap();
            }

            writeln!(file, "];\n").unwrap();
        }
    };
}

impl_write_masks!(write_masks_8, u8, 8, apply_8, 2);
impl_write_masks!(write_masks_16, u16, 16, apply_16, 4);
impl_write_masks!(write_masks_32, u32, 32, apply_32, 8);
impl_write_masks!(write_masks_64, u64, 64, apply_64, 16);
impl_write_masks!(write_masks_128, u128, 128, apply_128, 32);

// ==========================================
// 4. LIFT BASIS GENERATORS (FlatPromote)
// ==========================================

macro_rules! impl_write_lift {
    ($func_name:ident, $type:ty, $bits:expr, $apply_8_to_tower:ident, $apply_tower_to_n:ident, $width:expr) => {
        fn $func_name(
            file: &mut File,
            basis_name: &str,
            table_name: &str,
            flat_to_tower_8: &[u8; 8],
            tower_to_flat_n: &[$type; $bits],
        ) {
            // Generate 8-element basis for CT-math
            writeln!(
                file,
                "pub const {}: [{}; 8] = [",
                basis_name,
                stringify!($type)
            )
            .unwrap();

            for i in 0..8 {
                let flat_8 = 1u8 << i;
                let tower_8 = $apply_8_to_tower(flat_8, flat_to_tower_8);
                let tower_n = tower_8 as $type;
                let flat_n = $apply_tower_to_n(tower_n, tower_to_flat_n);

                writeln!(file, "    0x{:0width$x},", flat_n, width = $width).unwrap();
            }

            writeln!(file, "];\n").unwrap();

            // Generate 256-element table for table-math
            writeln!(
                file,
                "pub const {}: [{}; 256] = [",
                table_name,
                stringify!($type)
            )
            .unwrap();

            for val in 0..=255u8 {
                let tower_8 = $apply_8_to_tower(val, flat_to_tower_8);
                let tower_n = tower_8 as $type;
                let flat_n = $apply_tower_to_n(tower_n, tower_to_flat_n);

                writeln!(file, "    0x{:0width$x},", flat_n, width = $width).unwrap();
            }

            writeln!(file, "];\n").unwrap();
        }
    };
}

impl_write_lift!(write_lift_16, u16, 16, apply_8, apply_16, 4);
impl_write_lift!(write_lift_32, u32, 32, apply_8, apply_32, 8);
impl_write_lift!(write_lift_64, u64, 64, apply_8, apply_64, 16);
impl_write_lift!(write_lift_128, u128, 128, apply_8, apply_128, 32);

// ==========================================
// 5. GENERIC LIFT BASIS GENERATOR (For N -> 128)
// ==========================================

macro_rules! impl_write_lift_basis {
    ($func_name:ident, $type_from:ty, $type_to:ty, $bits:expr, $apply_flat_to_tower:ident, $apply_tower_to_flat:ident, $width:expr) => {
        fn $func_name(
            file: &mut File,
            basis_name: &str,
            flat_to_tower_from: &[$type_from; $bits],
            tower_to_flat_to: &[$type_to; 128],
        ) {
            writeln!(
                file,
                "pub const {}: [{}; {}] = [",
                basis_name,
                stringify!($type_to),
                $bits
            )
            .unwrap();

            for i in 0..$bits {
                let flat_from = (1 as $type_from) << i;
                let tower_from = $apply_flat_to_tower(flat_from, flat_to_tower_from);
                let tower_to = tower_from as $type_to;
                let flat_to = $apply_tower_to_flat(tower_to, tower_to_flat_to);

                writeln!(file, "    0x{:0width$x},", flat_to, width = $width).unwrap();
            }

            writeln!(file, "];\n").unwrap();
        }
    };
}

impl_write_lift_basis!(
    write_lift_basis_16_to_128,
    u16,
    u128,
    16,
    apply_16,
    apply_128,
    32
);
impl_write_lift_basis!(
    write_lift_basis_32_to_128,
    u32,
    u128,
    32,
    apply_32,
    apply_128,
    32
);
impl_write_lift_basis!(
    write_lift_basis_64_to_128,
    u64,
    u128,
    64,
    apply_64,
    apply_128,
    32
);

// ==========================================
// 6. RAW BASIS GENERATORS (For Constant-Time)
// ==========================================

macro_rules! impl_write_raw_basis {
    ($func_name:ident, $type:ty, $size:expr, $width:expr) => {
        fn $func_name(file: &mut File, name: &str, basis: &[$type; $size]) {
            writeln!(
                file,
                "pub const {}: [{}; {}] = [",
                name,
                stringify!($type),
                $size
            )
            .unwrap();

            for v in basis.iter() {
                writeln!(file, "    0x{:0width$x},", v, width = $width).unwrap();
            }

            writeln!(file, "];\n").unwrap();
        }
    };
}

impl_write_raw_basis!(write_raw_8, u8, 8, 2);
impl_write_raw_basis!(write_raw_16, u16, 16, 4);
impl_write_raw_basis!(write_raw_32, u32, 32, 8);
impl_write_raw_basis!(write_raw_64, u64, 64, 16);
impl_write_raw_basis!(write_raw_128, u128, 128, 32);

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated_constants.rs");

    let mut file = File::create(&dest_path).unwrap();

    writeln!(file, "// AUTO-GENERATED BY build.rs").unwrap();

    writeln!(file, "pub const POLY_8: u8 = 0x1b;").unwrap();
    writeln!(file, "pub const POLY_16: u16 = 0x002b;").unwrap();
    writeln!(file, "pub const POLY_32: u32 = 0x0000008d;").unwrap();
    writeln!(file, "pub const POLY_64: u64 = 0x000000000000001b;").unwrap();
    writeln!(
        file,
        "pub const POLY_128: u128 = 0x00000000000000000000000000000087;\n"
    )
    .unwrap();

    // 8 bit
    write_table_8(&mut file, "FLAT_TO_TOWER_8", &FLAT_TO_TOWER_8);
    write_table_8(&mut file, "TOWER_TO_FLAT_8", &TOWER_TO_FLAT_8);
    write_masks_8(&mut file, "FLAT_TO_TOWER_BIT_MASKS_8", &FLAT_TO_TOWER_8);
    write_raw_8(&mut file, "RAW_FLAT_TO_TOWER_8", &FLAT_TO_TOWER_8);
    write_raw_8(&mut file, "RAW_TOWER_TO_FLAT_8", &TOWER_TO_FLAT_8);

    // 16 bit
    write_table_16(&mut file, "FLAT_TO_TOWER_16", &FLAT_TO_TOWER_16);
    write_table_16(&mut file, "TOWER_TO_FLAT_16", &TOWER_TO_FLAT_16);
    write_masks_16(&mut file, "FLAT_TO_TOWER_BIT_MASKS_16", &FLAT_TO_TOWER_16);
    write_lift_16(
        &mut file,
        "LIFT_BASIS_8_TO_16",
        "LIFT_TABLE_8_TO_16",
        &FLAT_TO_TOWER_8,
        &TOWER_TO_FLAT_16,
    );
    write_raw_16(&mut file, "RAW_FLAT_TO_TOWER_16", &FLAT_TO_TOWER_16);
    write_raw_16(&mut file, "RAW_TOWER_TO_FLAT_16", &TOWER_TO_FLAT_16);

    // 32 bit
    write_table_32(&mut file, "FLAT_TO_TOWER_32", &FLAT_TO_TOWER_32);
    write_table_32(&mut file, "TOWER_TO_FLAT_32", &TOWER_TO_FLAT_32);
    write_masks_32(&mut file, "FLAT_TO_TOWER_BIT_MASKS_32", &FLAT_TO_TOWER_32);
    write_lift_32(
        &mut file,
        "LIFT_BASIS_8_TO_32",
        "LIFT_TABLE_8_TO_32",
        &FLAT_TO_TOWER_8,
        &TOWER_TO_FLAT_32,
    );
    write_raw_32(&mut file, "RAW_FLAT_TO_TOWER_32", &FLAT_TO_TOWER_32);
    write_raw_32(&mut file, "RAW_TOWER_TO_FLAT_32", &TOWER_TO_FLAT_32);

    // 64 bit
    write_table_64(&mut file, "FLAT_TO_TOWER_64", &FLAT_TO_TOWER_64);
    write_table_64(&mut file, "TOWER_TO_FLAT_64", &TOWER_TO_FLAT_64);
    write_masks_64(&mut file, "FLAT_TO_TOWER_BIT_MASKS_64", &FLAT_TO_TOWER_64);
    write_lift_64(
        &mut file,
        "LIFT_BASIS_8_TO_64",
        "LIFT_TABLE_8_TO_64",
        &FLAT_TO_TOWER_8,
        &TOWER_TO_FLAT_64,
    );
    write_raw_64(&mut file, "RAW_FLAT_TO_TOWER_64", &FLAT_TO_TOWER_64);
    write_raw_64(&mut file, "RAW_TOWER_TO_FLAT_64", &TOWER_TO_FLAT_64);

    // 128 bit
    write_table_128(&mut file, "FLAT_TO_TOWER_128", &FLAT_TO_TOWER_128);
    write_table_128(&mut file, "TOWER_TO_FLAT_128", &TOWER_TO_FLAT_128);
    write_masks_128(&mut file, "FLAT_TO_TOWER_BIT_MASKS_128", &FLAT_TO_TOWER_128);
    write_lift_128(
        &mut file,
        "LIFT_BASIS_8_TO_128",
        "LIFT_TABLE_8_TO_128",
        &FLAT_TO_TOWER_8,
        &TOWER_TO_FLAT_128,
    );
    write_raw_128(&mut file, "RAW_FLAT_TO_TOWER_128", &FLAT_TO_TOWER_128);
    write_raw_128(&mut file, "RAW_TOWER_TO_FLAT_128", &TOWER_TO_FLAT_128);

    // Extra lifting bases for
    // FlatPromote in Block128.
    write_lift_basis_16_to_128(
        &mut file,
        "LIFT_BASIS_16_TO_128",
        &FLAT_TO_TOWER_16,
        &TOWER_TO_FLAT_128,
    );
    write_lift_basis_32_to_128(
        &mut file,
        "LIFT_BASIS_32_TO_128",
        &FLAT_TO_TOWER_32,
        &TOWER_TO_FLAT_128,
    );
    write_lift_basis_64_to_128(
        &mut file,
        "LIFT_BASIS_64_TO_128",
        &FLAT_TO_TOWER_64,
        &TOWER_TO_FLAT_128,
    );

    println!("cargo:rerun-if-changed=build.rs");
}
