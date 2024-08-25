import crypto from "crypto";

function generateRandomKey(length: number): string {
  return crypto.randomBytes(length).toString("hex");
}

function encryptData(data: string, password: string): string {
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(password, "salt", 32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${encrypted}:${tag}`;
}

const PASSWORD =
  "251c34aab2b32a42f77bc8d1bea3f712c4a5b59a85183814bb68d151ee5fc3ae";

export const Modul_0 = {
  SHA_256: encryptData(generateRandomKey(32), PASSWORD),
  AES_256: encryptData(generateRandomKey(32), PASSWORD),
  UUI_128: encryptData(generateRandomKey(16), PASSWORD),
};

export const Modul_1 = {
  SALT_256: encryptData(generateRandomKey(32), PASSWORD),
  SALT_MIX: encryptData(generateRandomKey(16), PASSWORD),
};

export const Modul_2 = {
  METRIC: Array.from({ length: 17 }, () =>
    encryptData(generateRandomKey(8), PASSWORD)
  ),
};

export const Modul_3 = {
  JTRACK: encryptData(generateRandomKey(16), PASSWORD),
  DB_KEY: Array.from({ length: 10 }, () =>
    encryptData(generateRandomKey(8), PASSWORD)
  ),
  VIM_UUI: Array.from({ length: 10 }, () =>
    encryptData(generateRandomKey(32), PASSWORD)
  ),
};

// export const Modul_0 = {
//   SHA_256: "d37f774791cf05732a22606e673ba058de9711c6bf88765d1909b14c4499eb52",
//   AES_256: "4gozaqsaO8sxn4T8Ot1/ef+4QWp6K6kscfjwILqOWIoD+hCk0GVy7AZPqFp6RFA8",
//   UUI_128: "D+WzZ+m2avrC7too43YdnvDbOQUGG4YeZMiz0J/THwc=",
// };

// export const Modul_1 = {
//   SALT_256: "b6060d2c86b57a063fb5aa297e09e01154b10e799c967e53c9422d3ca047f11c",
//   SALT_MIX: "kmskgGReI18IoJdZw7grM/oM2Oie4OK/TJUP6M/m5vY=",
// };

// export const Modul_2 = {
//   METRIC: [
//     "0x370183053",
//     "0x730892978",
//     "0x509177492",
//     "0x188401424",
//     "0x944758932",
//     "0x424581289",
//     "0x773089823",
//     "0x948859035",
//     "0x599483214",
//     "0x389657838",
//     "0x968376835",
//     "0x968376837",
//     "0x633868375",
//     "0x385593856",
//     "0x991285782",
//     "0x235438683",
//     "0x883967375",
//   ],
// };

// export const Modul_3 = {
//   JTRACK: "ygJargL8maiHjN1O64tHZromwpjbNB94Fqq8v2Fzdl4=",
//   DB_KEY: [
//     "0/x/884947",
//     "0/x/500385",
//     "0/x/400841",
//     "0/x/530954",
//     "0/x/501745",
//     "0/x/301852",
//     "0/x/601364",
//     "0/x/593014",
//     "0/x/699204",
//     "0/x/689387",
//   ],
//   VIM_UUI: [
//     "udshfg978234yfuihb23789yr9yhsd789cvg23479b789fty4we",
//     "dfhn23$%#fln8932r#@%#$dfsnc9u234hr98f$%23fm98weffds",
//     "@#$%fmjhnwef@#$Rdnsfiudsbf23%#$%^snduidhfgbiuwesdfb",
//     "^@#423moifvjn23$#@%nfuiosdhfbn2!#$!@rsdifnsduiofn23",
//     "lksdhf332890s@#$ER23dnb87123easDSF3289@#$@#sdfubn3r",
//     "dshf@#%@#$rjnmfi234%$534239wef#!@fesdjnf32@#$#sadfs",
//     "sdnf12@!Ewsdqshdwasd@#%#$%@#sduijkfcbiuwe32$@#sdfhs",
//     "hjf123@#$dasniudh298FSDFSDF@#RWFasnuisdufcih23dsad2",
//     "DSFFG@#$R!@#DSniufdhfbsdl2#@$#@rwedjnsuiofOHBNUIOd3",
//     "dsnfb#$jkldshbfiuy32'$%#@4SDFSDFsdhuifbd@#$@sdfsddf",
//   ],
// };
