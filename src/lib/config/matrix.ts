import { createHash } from "crypto";

const matrix = [
  { "00001": "x044986201" },
  { "00011": "x046299425" },
  { "00111": "x068396837" },
  { "01111": "x037597534" },
  { "11111": "x038865483" },
  { "11110": "x085553062" },
  { "11100": "x018574365" },
  { "11000": "x019583467" },
  { "10000": "x082574963" },
  { "00000": "x099948378" },

  { "000001": "x0940294840293" },
  { "000011": "x0385738587375" },
  { "000111": "x0477693786893" },
  { "001111": "x0834757267583" },
  { "011111": "x0199785723656" },
  { "111111": "x0683768376357" },
  { "111110": "x0683768376834" },
  { "111100": "x0846767267636" },
  { "111000": "x0589275692356" },
  { "110000": "x0682868236767" },
  { "100000": "x0768276923765" },
  { "000000": "x0347868376938" },

  { "0x7847": "0xjdfj298f82nfd8238djc892nf8923" },
  { "0x8568": "0x937ugn23890vnusdcn89389hv8938" },
  { "0x7593": "0xmgfui27f2nsjvnw832hf823nv838f" },
  { "0x9625": "0xjcfj2jc82nf90926923mvfkd03u34" },
  { "0x3693": "0xfjm#dfjfdj!@kmvjfkmwsjf8923fg" },
];

export const getHashedMatrix = (): string[] => {
  return matrix
    .flatMap((element) =>
      Object.entries(element).map(([key, value]) => `$/@.${key}/#@.$${value}`)
    )
    .map((entry) => createHash("sha256").update(entry).digest("hex"));
};
