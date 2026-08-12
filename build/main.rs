// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>. All rights reserved.
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

#[allow(dead_code)]
mod gf_oracle {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/build/gf_oracle.rs"));
}

// Mirror constants::POLY_* and Block8::EXTENSION_TAU.
// x^k + POLY_k is the flat-basis modulus; verify_isomorphism_*
// and write_algebra_extras_16 pin them against the oracle at build time.
const POLY_8: u8 = 0x1b;
const POLY_16: u16 = 0x2b;
const POLY_32: u32 = 0x8d;
const POLY_64: u64 = 0x1b;
const POLY_128: u128 = 0x87;

const EXTENSION_TAU_8: u8 = 0x20;

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

// ==========================================
// 7. BYTE-DECOMPOSED PROMOTE TABLES
// ==========================================
//
// For promoting Block16/32/64 to Block128 via
// table-math. Each source byte position gets
// its own [u128; 256] table. The full promote
// is the XOR of per-byte lookups (GF(2)-linear).
//
// Block8 to Block128 is a single-byte source,
// so it uses LIFT_TABLE_8_TO_128 from section 4
// (no byte decomposition needed).

macro_rules! impl_write_promote_byte_tables_to_128 {
    ($func_name:ident, $from_type:ty, $n_bytes:expr, $apply_from:ident) => {
        fn $func_name(
            file: &mut File,
            prefix: &str,
            flat_to_tower_from: &[$from_type; $n_bytes * 8],
        ) {
            for byte_idx in 0..$n_bytes {
                writeln!(
                    file,
                    "pub const {}_{}_TO_128: [u128; 256] = [",
                    prefix, byte_idx
                )
                .unwrap();

                for val in 0..=255u8 {
                    let from_val = (val as $from_type) << (byte_idx * 8);
                    let tower_from = $apply_from(from_val, flat_to_tower_from);
                    let tower_128 = tower_from as u128;
                    let flat_128 = apply_128(tower_128, &TOWER_TO_FLAT_128);

                    writeln!(file, "    0x{:032x},", flat_128).unwrap();
                }

                writeln!(file, "];\n").unwrap();
            }
        }
    };
}

impl_write_promote_byte_tables_to_128!(write_promote_byte_tables_16_to_128, u16, 2, apply_16);
impl_write_promote_byte_tables_to_128!(write_promote_byte_tables_32_to_128, u32, 4, apply_32);
impl_write_promote_byte_tables_to_128!(write_promote_byte_tables_64_to_128, u64, 8, apply_64);

// ==========================================
// 8. NIBBLE-DECOMPOSED PROMOTE TABLES (CT NEON)
// ==========================================
//
// For constant-time NEON promotion via vqtbl1q_u8.
// Split each source element into 4-bit nibbles,
// look up the contribution of each nibble to each
// output byte position. GF(2)-linearity guarantees
// the full promote is XOR of all nibble contributions.
//
// Layout per nibble position:
//   [output_byte_pos][nibble_value] → u8
//   16 output bytes × 16 nibble values = 256 bytes.
//
// | Source  | Nibbles | Tables | Total bytes |
// |---------|---------|--------|-------------|
// | Block8  | 2       | 2×256  | 512         |
// | Block16 | 4       | 4×256  | 1024        |
// | Block32 | 8       | 8×256  | 2048        |
// | Block64 | 16      | 16×256 | 4096        |

macro_rules! impl_write_nibble_promote_tables_to_128 {
    ($func_name:ident, $from_type:ty, $n_nibbles:expr, $apply_from:ident) => {
        fn $func_name(
            file: &mut File,
            prefix: &str,
            flat_to_tower_from: &[$from_type; <$from_type>::BITS as usize],
            tower_to_flat_from: &[$from_type; <$from_type>::BITS as usize],
        ) {
            for nib_idx in 0..$n_nibbles {
                // Precompute full 128-bit lift for all
                // 16 values of this nibble position.
                let mut lifted = [0u128; 16];

                for nibble in 0u8..16 {
                    let from_val = (nibble as $from_type) << (nib_idx * 4);
                    let tower_from = $apply_from(from_val, flat_to_tower_from);
                    let tower_128 = tower_from as u128;

                    lifted[nibble as usize] = apply_128(tower_128, &TOWER_TO_FLAT_128);

                    // Every entry round-trips through the mutually-inverse
                    // matrices at both widths: pins the tables against
                    // a corrupted matrix or transport, independent of
                    // the generating direction.
                    assert_eq!(
                        apply_128(lifted[nibble as usize], &FLAT_TO_TOWER_128),
                        tower_128,
                        "{prefix}: 128-side round-trip broken at nib {nib_idx}, value {nibble}"
                    );
                    assert_eq!(
                        $apply_from(tower_from, tower_to_flat_from),
                        from_val,
                        "{prefix}: source-side round-trip broken at nib {nib_idx}, value {nibble}"
                    );
                }

                writeln!(
                    file,
                    "pub const {}_{}_TO_128: [[u8; 16]; 16] = [",
                    prefix, nib_idx
                )
                .unwrap();

                for byte_pos in 0..16usize {
                    write!(file, "    [").unwrap();

                    for nibble in 0..16usize {
                        let b = ((lifted[nibble] >> (byte_pos * 8)) & 0xFF) as u8;
                        write!(file, "0x{:02x}", b).unwrap();

                        if nibble < 15 {
                            write!(file, ", ").unwrap();
                        }
                    }

                    writeln!(file, "],").unwrap();
                }

                writeln!(file, "];\n").unwrap();
            }
        }
    };
}

impl_write_nibble_promote_tables_to_128!(write_nibble_promote_8_to_128, u8, 2, apply_8);
impl_write_nibble_promote_tables_to_128!(write_nibble_promote_16_to_128, u16, 4, apply_16);
impl_write_nibble_promote_tables_to_128!(write_nibble_promote_32_to_128, u32, 8, apply_32);
impl_write_nibble_promote_tables_to_128!(write_nibble_promote_64_to_128, u64, 16, apply_64);

// ==========================================
// 9. ALGEBRAIC EXTRAS (Block16, GF(2^16))
// ==========================================
//
// Block16 = Block8[X]/(X^2 + X + 0x20) over the
// AES field (0x1b). Trace and the Artin-Schreier
// operator L(x) = x^2 + x reduce to squaring, so
// tower squaring is the only field op needed here.

fn gf8_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    let mut i = 0;

    while i < 8 {
        if b & 1 == 1 {
            res ^= a;
        }

        let carry = a & 0x80;

        a <<= 1;

        if carry != 0 {
            a ^= POLY_8;
        }

        b >>= 1;
        i += 1;
    }

    res
}

fn sq16_tower(a: u16) -> u16 {
    let lo = (a & 0x00ff) as u8;
    let hi = (a >> 8) as u8;

    let lo2 = gf8_mul(lo, lo);
    let hi2 = gf8_mul(hi, hi);
    let new_lo = lo2 ^ gf8_mul(hi2, EXTENSION_TAU_8);

    ((hi2 as u16) << 8) | (new_lo as u16)
}

fn flat_sq_16(a: u16) -> u16 {
    let mut acc = 0u32;

    for i in 0..16 {
        if (a >> i) & 1 == 1 {
            acc ^= 1u32 << (2 * i);
        }
    }

    for i in (16..32).rev() {
        if (acc >> i) & 1 == 1 {
            acc ^= (1u32 << i) ^ ((POLY_16 as u32) << (i - 16));
        }
    }

    acc as u16
}

macro_rules! impl_algebra_helpers {
    ($trace_of:ident, $invert:ident, $rank:ident, $vanish:ident, $ty:ty, $bits:expr, $sq:ident) => {
        fn $trace_of(x: $ty) -> $ty {
            let mut acc: $ty = 0;
            let mut p = x;
            let mut i = 0;

            while i < $bits {
                acc ^= p;
                p = $sq(p);
                i += 1;
            }

            acc
        }

        // cols[k] and the result are column-image form:
        // column k is the image of basis vector e_k.
        fn $invert(cols: &[$ty; $bits]) -> [$ty; $bits] {
            let mut rows = [0 as $ty; $bits];
            let mut inv = [0 as $ty; $bits];

            for (i, slot) in inv.iter_mut().enumerate() {
                *slot = (1 as $ty) << i;
            }

            for (i, row) in rows.iter_mut().enumerate() {
                for (k, &col) in cols.iter().enumerate() {
                    *row |= ((col >> i) & 1) << k;
                }
            }

            for col in 0..$bits {
                let mut piv = col;
                while piv < $bits && (rows[piv] >> col) & 1 == 0 {
                    piv += 1;
                }

                assert!(
                    piv < $bits,
                    "Artin-Schreier operator is singular: field constants are inconsistent"
                );

                rows.swap(col, piv);
                inv.swap(col, piv);

                for r in 0..$bits {
                    if r != col && (rows[r] >> col) & 1 == 1 {
                        rows[r] ^= rows[col];
                        inv[r] ^= inv[col];
                    }
                }
            }

            let mut out = [0 as $ty; $bits];
            for (k, slot) in out.iter_mut().enumerate() {
                for (i, &v) in inv.iter().enumerate() {
                    *slot |= ((v >> k) & 1) << i;
                }
            }

            out
        }

        fn $vanish(i: usize, x: $ty) -> $ty {
            let mut t = x;
            for _ in 0..i {
                t = $sq(t) ^ t;
            }

            t
        }

        fn $rank(vals: &[$ty; $bits]) -> usize {
            let mut piv = [0 as $ty; $bits];
            let mut rank = 0;

            for &v in vals.iter() {
                let mut x = v;
                while x != 0 {
                    let b = x.trailing_zeros() as usize;
                    if piv[b] == 0 {
                        piv[b] = x;
                        rank += 1;

                        break;
                    }

                    x ^= piv[b];
                }
            }

            rank
        }
    };
}

impl_algebra_helpers!(
    trace_of_16,
    gf2_invert_16,
    gf2_rank_16,
    vanish_build_16,
    u16,
    16,
    sq16_tower
);

// Flat reference product, per gf_model.rs:
// gf_mul(a, b, k) = pmod(clmul(a, b), x^k + POLY_k).
// pmod folds each high bit down by POLY_k to a strictly
// lower position, one descending sweep clears hi.
macro_rules! impl_gf_mul_flat {
    ($clmul:ident, $pmod:ident, $gf_mul_flat:ident, $type:ty, $size:expr, $poly:expr) => {
        fn $clmul(a: $type, b: $type) -> ($type, $type) {
            let mut lo: $type = 0;
            let mut hi: $type = 0;

            for i in 0..$size {
                if (b >> i) & 1 == 1 {
                    if i == 0 {
                        lo ^= a;
                    } else {
                        lo ^= a << i;
                        hi ^= a >> ($size - i);
                    }
                }
            }

            (lo, hi)
        }

        fn $pmod(mut lo: $type, mut hi: $type) -> $type {
            for pos in (0..$size).rev() {
                if (hi >> pos) & 1 == 1 {
                    hi ^= (1 as $type) << pos;

                    if pos == 0 {
                        lo ^= $poly;
                    } else {
                        lo ^= $poly << pos;
                        hi ^= $poly >> ($size - pos);
                    }
                }
            }

            lo
        }

        fn $gf_mul_flat(a: $type, b: $type) -> $type {
            let (lo, hi) = $clmul(a, b);
            $pmod(lo, hi)
        }
    };
}

impl_gf_mul_flat!(clmul_8, pmod_8, gf_mul_flat_8, u8, 8, POLY_8);
impl_gf_mul_flat!(clmul_16, pmod_16, gf_mul_flat_16, u16, 16, POLY_16);
impl_gf_mul_flat!(clmul_32, pmod_32, gf_mul_flat_32, u32, 32, POLY_32);
impl_gf_mul_flat!(clmul_64, pmod_64, gf_mul_flat_64, u64, 64, POLY_64);
impl_gf_mul_flat!(clmul_128, pmod_128, gf_mul_flat_128, u128, 128, POLY_128);

// verify_isomorphism_N pins these matrices and
// the flat product against the tower oracle.
macro_rules! impl_sq_transport {
    ($sq:ident, $ty:ty, $apply:ident, $mul_flat:ident, $t2f:ident, $f2t:ident) => {
        fn $sq(x: $ty) -> $ty {
            let f = $apply(x, &$t2f);

            $apply($mul_flat(f, f), &$f2t)
        }
    };
}

impl_sq_transport!(
    sq32_tower,
    u32,
    apply_32,
    gf_mul_flat_32,
    TOWER_TO_FLAT_32,
    FLAT_TO_TOWER_32
);
impl_sq_transport!(
    sq64_tower,
    u64,
    apply_64,
    gf_mul_flat_64,
    TOWER_TO_FLAT_64,
    FLAT_TO_TOWER_64
);
impl_sq_transport!(
    sq128_tower,
    u128,
    apply_128,
    gf_mul_flat_128,
    TOWER_TO_FLAT_128,
    FLAT_TO_TOWER_128
);

impl_algebra_helpers!(
    trace_of_32,
    gf2_invert_32,
    gf2_rank_32,
    vanish_build_32,
    u32,
    32,
    sq32_tower
);
impl_algebra_helpers!(
    trace_of_64,
    gf2_invert_64,
    gf2_rank_64,
    vanish_build_64,
    u64,
    64,
    sq64_tower
);
impl_algebra_helpers!(
    trace_of_128,
    gf2_invert_128,
    gf2_rank_128,
    vanish_build_128,
    u128,
    128,
    sq128_tower
);

macro_rules! impl_verify_iso {
    ($func:ident, $type:ty, $size:expr, $gf_mul_flat:ident, $apply:ident,
     $schoolbook:path, $tower_to_flat:ident, $flat_to_tower:ident) => {
        fn $func() {
            for i in 0..$size {
                let e = (1 as $type) << i;

                assert_eq!(
                    $gf_mul_flat(1, e),
                    e,
                    "GF(2^{}): flat 1 is not identity",
                    $size
                );
                assert_eq!(
                    $gf_mul_flat(e, 0),
                    0,
                    "GF(2^{}): flat 0 is not absorbing",
                    $size
                );
                assert_eq!(
                    $schoolbook(1, e),
                    e,
                    "GF(2^{}): tower 1 is not identity",
                    $size
                );

                assert_eq!(
                    $apply($apply(e, &$tower_to_flat), &$flat_to_tower),
                    e,
                    "GF(2^{}): FLAT_TO_TOWER not inverse of TOWER_TO_FLAT (bit {})",
                    $size,
                    i
                );
                assert_eq!(
                    $apply($apply(e, &$flat_to_tower), &$tower_to_flat),
                    e,
                    "GF(2^{}): TOWER_TO_FLAT not inverse of FLAT_TO_TOWER (bit {})",
                    $size,
                    i
                );
            }

            for i in 0..$size {
                let phi_ei = $apply((1 as $type) << i, &$tower_to_flat);

                for j in 0..$size {
                    let phi_ej = $apply((1 as $type) << j, &$tower_to_flat);
                    let via_tower = $apply(
                        $schoolbook((1 as $type) << i, (1 as $type) << j),
                        &$tower_to_flat,
                    );
                    let via_flat = $gf_mul_flat(phi_ei, phi_ej);

                    assert_eq!(
                        via_tower, via_flat,
                        "GF(2^{}): change-of-basis not multiplicative at ({}, {})",
                        $size, i, j
                    );
                }
            }
        }
    };
}

impl_verify_iso!(
    verify_isomorphism_8,
    u8,
    8,
    gf_mul_flat_8,
    apply_8,
    gf_oracle::schoolbook8,
    TOWER_TO_FLAT_8,
    FLAT_TO_TOWER_8
);
impl_verify_iso!(
    verify_isomorphism_16,
    u16,
    16,
    gf_mul_flat_16,
    apply_16,
    gf_oracle::schoolbook16,
    TOWER_TO_FLAT_16,
    FLAT_TO_TOWER_16
);
impl_verify_iso!(
    verify_isomorphism_32,
    u32,
    32,
    gf_mul_flat_32,
    apply_32,
    gf_oracle::schoolbook32,
    TOWER_TO_FLAT_32,
    FLAT_TO_TOWER_32
);
impl_verify_iso!(
    verify_isomorphism_64,
    u64,
    64,
    gf_mul_flat_64,
    apply_64,
    gf_oracle::schoolbook64,
    TOWER_TO_FLAT_64,
    FLAT_TO_TOWER_64
);
impl_verify_iso!(
    verify_isomorphism_128,
    u128,
    128,
    gf_mul_flat_128,
    apply_128,
    gf_oracle::schoolbook128,
    TOWER_TO_FLAT_128,
    FLAT_TO_TOWER_128
);

// Build-time discharge of verus/axioms_t.rs::norm_nonzero: the norm N(a) has
// no nonzero root (GF(2^{2m}) is a field) iff X^2+X+tau_m is irreducible over GF(2^m)
// iff Tr_{GF(2^m)/GF(2)}(tau_m) = 1 (Artin-Schreier). tau_m is EXTENSION_TAU in
// the tower basis (see gf_oracle::schoolbook*); 1 is the tower identity.
fn verify_norm_anisotropy() {
    let (mut t, mut p) = (0u8, 0x20u8);
    for _ in 0..8 {
        t ^= p;
        p = gf_oracle::sb8(p, p);
    }

    assert_eq!(
        t, 1,
        "GF(2^16) not a field: Tr(tau_8) != 1 (X^2+X+0x20 reducible over GF(2^8))"
    );

    let (mut t, mut p) = (0u16, 0x2000u16);
    for _ in 0..16 {
        t ^= p;
        p = gf_oracle::schoolbook16(p, p);
    }

    assert_eq!(
        t, 1,
        "GF(2^32) not a field: Tr(tau_16) != 1 (X^2+X+tau_16 reducible over GF(2^16))"
    );

    let (mut t, mut p) = (0u32, 0x2000_0000u32);
    for _ in 0..32 {
        t ^= p;
        p = gf_oracle::schoolbook32(p, p);
    }

    assert_eq!(
        t, 1,
        "GF(2^64) not a field: Tr(tau_32) != 1 (X^2+X+tau_32 reducible over GF(2^32))"
    );

    let (mut t, mut p) = (0u64, 0x2000_0000_0000_0000u64);
    for _ in 0..64 {
        t ^= p;
        p = gf_oracle::schoolbook64(p, p);
    }

    assert_eq!(
        t, 1,
        "GF(2^128) not a field: Tr(tau_64) != 1 (X^2+X+tau_64 reducible over GF(2^64))"
    );

    let (mut t, mut p) = (0u128, 0x20u128 << 120);
    for _ in 0..128 {
        t ^= p;
        p = gf_oracle::schoolbook128(p, p);
    }

    assert_eq!(
        t, 1,
        "GF(2^256) not a field: Tr(tau_128) != 1 (X^2+X+tau_128 reducible over GF(2^128))"
    );
}

// Build-time discharge of verus/axioms_t.rs::frobenius_order_gen:
// e_i^(2^m) = e_i for every single-bit generator of GF(2^m),
// squaring through the same shared gf_oracle::schoolbook*.
fn verify_frobenius_order() {
    for i in 0..8 {
        let e = 1u8 << i;

        let mut p = e;
        for _ in 0..8 {
            p = gf_oracle::sb8(p, p);
        }

        assert_eq!(p, e, "GF(2^8): e_{i} not fixed by x^(2^8)");
    }

    for i in 0..16 {
        let e = 1u16 << i;

        let mut p = e;
        for _ in 0..16 {
            p = gf_oracle::schoolbook16(p, p);
        }

        assert_eq!(p, e, "GF(2^16): e_{i} not fixed by x^(2^16)");
    }

    for i in 0..32 {
        let e = 1u32 << i;

        let mut p = e;
        for _ in 0..32 {
            p = gf_oracle::schoolbook32(p, p);
        }

        assert_eq!(p, e, "GF(2^32): e_{i} not fixed by x^(2^32)");
    }

    for i in 0..64 {
        let e = 1u64 << i;

        let mut p = e;
        for _ in 0..64 {
            p = gf_oracle::schoolbook64(p, p);
        }

        assert_eq!(p, e, "GF(2^64): e_{i} not fixed by x^(2^64)");
    }

    for i in 0..128 {
        let e = 1u128 << i;

        let mut p = e;
        for _ in 0..128 {
            p = gf_oracle::schoolbook128(p, p);
        }

        assert_eq!(p, e, "GF(2^128): e_{i} not fixed by x^(2^128)");
    }
}

fn write_algebra_extras_16(file: &mut File) {
    // FIPS-197 §4.2 worked example pins POLY_8.
    assert_eq!(gf8_mul(0x57, 0x83), 0xc1, "gf8_mul is not the AES field");

    let mut trace_mask = 0u16;
    for k in 0..16 {
        if trace_of_16(1 << k) == 1 {
            trace_mask |= 1 << k;
        }
    }

    // L(x) = x^2 + x has kernel {0, 1}, so it is not
    // invertible. Lift to L~(x) = L(x) + (bit0 x)*d with
    // d outside the trace-zero image; then L~^-1 on the
    // trace-zero subspace solves x^2 + x = c (Tr c = 0).
    assert_ne!(
        trace_mask, 0,
        "trace functional is identically zero: field is broken"
    );

    let d = 1u16 << trace_mask.trailing_zeros();

    let mut l_tilde = [0u16; 16];
    for (k, slot) in l_tilde.iter_mut().enumerate() {
        let l_k = sq16_tower(1 << k) ^ (1u16 << k);
        *slot = l_k ^ if k == 0 { d } else { 0 };
    }

    let solve_basis = gf2_invert_16(&l_tilde);

    // Build-time proof: trace laws + solvability.
    let mut trace_zero = 0u32;
    for x in 0u16..=u16::MAX {
        let t = trace_of_16(x);
        assert!(t <= 1, "trace escaped GF(2)");

        let parity = ((x & trace_mask).count_ones() & 1) as u16;
        assert_eq!(parity, t, "TRACE_MASK_16 does not reproduce the trace");

        let via_basis = apply_16(
            flat_sq_16(apply_16(x, &TOWER_TO_FLAT_16)),
            &FLAT_TO_TOWER_16,
        );
        assert_eq!(
            sq16_tower(x),
            via_basis,
            "tower squaring disagrees with the change-of-basis oracle: \
             EXTENSION_TAU_8/POLY_8/POLY_16 inconsistent with the basis matrices"
        );

        if t == 0 {
            trace_zero += 1;

            let root = apply_16(x, &solve_basis);
            assert_eq!(
                sq16_tower(root) ^ root,
                x,
                "SOLVE_QUADRATIC_BASIS_16 fails the round-trip x^2 + x = c"
            );
        }
    }

    assert_eq!(trace_of_16(1), 0, "Tr(1) must vanish in GF(2^16)");
    assert_eq!(trace_zero, 32768, "trace functional is unbalanced");

    writeln!(file, "pub const TRACE_MASK_16: u16 = 0x{trace_mask:04x};\n").unwrap();
    write_raw_16(file, "SOLVE_QUADRATIC_BASIS_16", &solve_basis);

    // Cantor basis:
    // β_0 = 1,
    // β_i solves x^2 + x = β_{i-1}.
    let mut cantor_tower = [0u16; 16];
    cantor_tower[0] = 1;

    for i in 1..16 {
        cantor_tower[i] = apply_16(cantor_tower[i - 1], &solve_basis);
    }

    // V10 self-check:
    // independence, β_0 = 1, σ(β_i) = β_{i-1},
    // s_i(β_i) = 1,
    // Tr(β_i) = 0 for i < 15 and Tr(β_15) = 1.
    assert_eq!(
        gf2_rank_16(&cantor_tower),
        16,
        "Cantor basis is GF(2)-dependent"
    );
    assert_eq!(cantor_tower[0], 1, "beta_0 must be 1");

    for i in 0..16 {
        assert_eq!(vanish_build_16(i, cantor_tower[i]), 1, "s_i(beta_i) != 1");

        let tr = (cantor_tower[i] & trace_mask).count_ones() & 1;
        if i < 15 {
            assert_eq!(tr, 0, "Tr(beta_i) must vanish for i < 15");
        } else {
            assert_eq!(tr, 1, "Tr(beta_15) must be 1");
        }

        if i >= 1 {
            assert_eq!(
                sq16_tower(cantor_tower[i]) ^ cantor_tower[i],
                cantor_tower[i - 1],
                "Cantor chain broken: sigma(beta_i) != beta_(i-1)"
            );
        }
    }

    // The FFT applies sigma in the flat basis; pin the chain
    // there too, independent of the isomorphism transport.
    let mut prev_flat = apply_16(cantor_tower[0], &TOWER_TO_FLAT_16);
    assert_eq!(prev_flat, 1, "flat Cantor basis must start at 1");

    for &beta in cantor_tower.iter().skip(1) {
        let bf = apply_16(beta, &TOWER_TO_FLAT_16);

        assert_eq!(
            flat_sq_16(bf) ^ bf,
            prev_flat,
            "flat Cantor chain broken: sigma_flat(beta_i) != beta_(i-1)"
        );

        prev_flat = bf;
    }

    write_raw_16(file, "CANTOR_BASIS_TOWER_16", &cantor_tower);
}

fn xorshift64(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;

    *s
}

macro_rules! impl_write_algebra_extras_wide {
    ($fname:ident, $ty:ty, $bits:expr, $hexw:expr, $sq:ident, $apply:ident,
     $invert:ident, $rank:ident, $vanish:ident, $trace_of:ident, $write_raw:ident,
     $mask_name:literal, $basis_name:literal, $seed:literal) => {
        fn $fname(file: &mut File) {
            let mut trace_mask: $ty = 0;
            for k in 0..$bits {
                if $trace_of((1 as $ty) << k) == 1 {
                    trace_mask |= (1 as $ty) << k;
                }
            }

            assert_ne!(
                trace_mask, 0,
                "trace functional is identically zero: field is broken"
            );
            assert_eq!(
                $trace_of(1),
                0,
                "Tr(1) must vanish in an even-degree extension"
            );

            let d: $ty = (1 as $ty) << trace_mask.trailing_zeros();
            assert_eq!((d & trace_mask).count_ones() & 1, 1, "Tr(d) must be 1");

            let mut l_tilde = [0 as $ty; $bits];
            for (k, slot) in l_tilde.iter_mut().enumerate() {
                let e = (1 as $ty) << k;
                let l_k = $sq(e) ^ e;
                *slot = l_k ^ if k == 0 { d } else { 0 };
            }

            let solve_basis = $invert(&l_tilde);

            for k in 0..$bits {
                let e = (1 as $ty) << k;

                assert_eq!(
                    $apply(l_tilde[k], &solve_basis),
                    e,
                    "solve o L~ != id on basis vector {}",
                    k
                );
                assert_eq!(
                    $apply(solve_basis[k], &l_tilde),
                    e,
                    "L~ o solve != id on basis vector {}",
                    k
                );
            }

            // Roots of y^2 + y = x^2 + x are exactly {x, x + 1}
            let mut s: u64 = $seed;
            for _ in 0..64 {
                let x =
                    (((xorshift64(&mut s) as u128) << 64) | (xorshift64(&mut s) as u128)) as $ty;
                let c = $sq(x) ^ x;

                assert_eq!(
                    (c & trace_mask).count_ones() & 1,
                    0,
                    "Tr(x^2 + x) must vanish"
                );

                let root = $apply(c, &solve_basis);
                assert!(
                    root == x || root == (x ^ 1),
                    "solve returned a value outside the root pair"
                );
                assert_eq!($sq(root) ^ root, c, "solve round-trip failed");
            }

            let mut chain = [0 as $ty; $bits];
            chain[0] = 1;

            for i in 1..$bits {
                chain[i] = $apply(chain[i - 1], &solve_basis);
            }

            assert_eq!($rank(&chain), $bits, "Cantor basis is GF(2)-dependent");

            for (i, &b) in chain.iter().enumerate() {
                assert_eq!($vanish(i, b), 1, "s_i(beta_i) != 1");

                let tr = (b & trace_mask).count_ones() & 1;
                assert_eq!(
                    tr == 1,
                    i == $bits - 1,
                    "Cantor chain trace pattern broken at {}",
                    i
                );

                if i >= 1 {
                    assert_eq!(
                        $sq(b) ^ b,
                        chain[i - 1],
                        "Cantor chain broken: sigma(beta_i) != beta_(i-1)"
                    );
                }
            }

            writeln!(
                file,
                "pub const {}: {} = 0x{:0w$x};\n",
                $mask_name,
                stringify!($ty),
                trace_mask,
                w = $hexw
            )
            .unwrap();
            $write_raw(file, $basis_name, &solve_basis);
        }
    };
}

impl_write_algebra_extras_wide!(
    write_algebra_extras_32,
    u32,
    32,
    8,
    sq32_tower,
    apply_32,
    gf2_invert_32,
    gf2_rank_32,
    vanish_build_32,
    trace_of_32,
    write_raw_32,
    "TRACE_MASK_32",
    "SOLVE_QUADRATIC_BASIS_32",
    0x7365_6564_5f72_7333u64
);
impl_write_algebra_extras_wide!(
    write_algebra_extras_64,
    u64,
    64,
    16,
    sq64_tower,
    apply_64,
    gf2_invert_64,
    gf2_rank_64,
    vanish_build_64,
    trace_of_64,
    write_raw_64,
    "TRACE_MASK_64",
    "SOLVE_QUADRATIC_BASIS_64",
    0x7365_6564_5f72_7336u64
);
impl_write_algebra_extras_wide!(
    write_algebra_extras_128,
    u128,
    128,
    32,
    sq128_tower,
    apply_128,
    gf2_invert_128,
    gf2_rank_128,
    vanish_build_128,
    trace_of_128,
    write_raw_128,
    "TRACE_MASK_128",
    "SOLVE_QUADRATIC_BASIS_128",
    0x7365_6564_5f72_7331u64
);

// Gate PMULL on `aes`, not on the arch:
// without the feature core's vmull_p64 stays out-of-line and
// spills operands, and a core lacking the extension SIGILLs.
fn emit_pmull_cfg() {
    println!("cargo::rerun-if-env-changed=CARGO_CFG_TARGET_FEATURE");
    println!("cargo::rustc-check-cfg=cfg(pmull)");

    let aarch64 = env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64");
    let aes = env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .split(',')
        .any(|f| f == "aes");

    if aarch64 && aes {
        println!("cargo::rustc-cfg=pmull");
    }
}

fn main() {
    verify_isomorphism_8();
    verify_isomorphism_16();
    verify_isomorphism_32();
    verify_isomorphism_64();
    verify_isomorphism_128();
    verify_norm_anisotropy();
    verify_frobenius_order();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated_constants.rs");

    let mut file = File::create(&dest_path).unwrap();

    writeln!(file, "// AUTO-GENERATED BY build/main.rs").unwrap();

    writeln!(file, "pub const POLY_8: u8 = 0x{POLY_8:02x};").unwrap();
    writeln!(file, "pub const POLY_16: u16 = 0x{POLY_16:04x};").unwrap();
    writeln!(file, "pub const POLY_32: u32 = 0x{POLY_32:08x};").unwrap();
    writeln!(file, "pub const POLY_64: u64 = 0x{POLY_64:016x};").unwrap();
    writeln!(file, "pub const POLY_128: u128 = 0x{POLY_128:032x};\n").unwrap();

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

    write_algebra_extras_16(&mut file);

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

    write_algebra_extras_32(&mut file);

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

    write_algebra_extras_64(&mut file);

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

    write_algebra_extras_128(&mut file);

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

    // Byte-decomposed promote tables
    // for Block16/32/64 to Block128.
    write_promote_byte_tables_16_to_128(&mut file, "PROMOTE_16_BYTE", &FLAT_TO_TOWER_16);
    write_promote_byte_tables_32_to_128(&mut file, "PROMOTE_32_BYTE", &FLAT_TO_TOWER_32);
    write_promote_byte_tables_64_to_128(&mut file, "PROMOTE_64_BYTE", &FLAT_TO_TOWER_64);

    // Nibble-decomposed promote tables
    // for CT NEON promotion to Block128.
    write_nibble_promote_8_to_128(
        &mut file,
        "NIBBLE_PROMOTE_8",
        &FLAT_TO_TOWER_8,
        &TOWER_TO_FLAT_8,
    );
    write_nibble_promote_16_to_128(
        &mut file,
        "NIBBLE_PROMOTE_16",
        &FLAT_TO_TOWER_16,
        &TOWER_TO_FLAT_16,
    );
    write_nibble_promote_32_to_128(
        &mut file,
        "NIBBLE_PROMOTE_32",
        &FLAT_TO_TOWER_32,
        &TOWER_TO_FLAT_32,
    );
    write_nibble_promote_64_to_128(
        &mut file,
        "NIBBLE_PROMOTE_64",
        &FLAT_TO_TOWER_64,
        &TOWER_TO_FLAT_64,
    );

    emit_pmull_cfg();

    println!("cargo::rerun-if-changed=build/main.rs");
    println!("cargo::rerun-if-changed=build/gf_oracle.rs");
}
