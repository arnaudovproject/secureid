import { createHash, randomBytes } from "crypto";
import { Modul_0, Modul_1, Modul_2, Modul_3 } from "../config/keygen";
import { getHashedMatrix } from "../config/matrix";

export class Trust {
  private _key: string[] = [];
  private _userKey: string;

  private readonly SHA_256: string = Modul_0.SHA_256;
  private readonly AES_256: string = Modul_0.AES_256;
  private readonly UUI_128: string = Modul_0.UUI_128;

  private readonly SALT_256: string = Modul_1.SALT_256;
  private readonly SALT_MIX: string = Modul_1.SALT_MIX;

  private readonly METRIC: string[] = Modul_2.METRIC;

  private readonly JTRACK: string = Modul_3.JTRACK;
  private readonly DB_KEY: string[] = Modul_3.DB_KEY;
  private readonly VIM_UUI: string[] = Modul_3.VIM_UUI;

  private readonly HASHED_MATRIX: string[] = getHashedMatrix();

  constructor(userKey: string) {
    if (typeof userKey !== "string" || userKey.trim().length === 0) {
      throw new Error("Invalid userKey: must be a non-empty string.");
    }
    this._userKey = userKey;
    this.logical();
  }

  private logical(): void {
    try {
      const _SHA_256 = this.SHA_256.substring(0, 29);
      const _AES_256 = this.AES_256.slice(-19);
      const _UUI_128 = this.UUI_128;

      const _SALT_256 = this.SALT_256;
      const _SALT_MIX = this.SALT_MIX.slice(-15);

      const _METRIC = this.getRandomElement(this.METRIC);

      const _JTRACK = this.JTRACK.substring(8, 21);

      const _DB_KEY = this.getRandomElement(this.DB_KEY);

      const _VIM_UUI = this.getRandomElement(this.VIM_UUI);

      const _HASHED_MATRIX = this.HASHED_MATRIX;

      // Генериране на криптографски сигурен произволен salt
      const randomSalt = randomBytes(16).toString("hex");

      // Включване на hash на всяко matrix
      _HASHED_MATRIX.forEach((matrix) => {
        try {
          this.createHash([matrix, randomSalt]);
        } catch (error: unknown) {
          if (error instanceof Error) {
            console.error("Error hashing matrix:", error.message);
          } else {
            console.error("Unexpected error:", error);
          }
        }
      });

      // Създаване на финален hash с включване на randomSalt и userKey
      try {
        this.createHash([
          _SHA_256,
          _AES_256,
          _UUI_128,
          _SALT_256,
          _SALT_MIX,
          _METRIC,
          _JTRACK,
          _DB_KEY,
          _VIM_UUI,
          this._userKey,
          randomSalt,
        ]);
      } catch (error: unknown) {
        if (error instanceof Error) {
          console.error("Error creating final hash:", error.message);
        } else {
          console.error("Unexpected error:", error);
        }
      }
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error in logical method:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed during logical processing.");
    }
  }

  private createHash(data: string[]): void {
    try {
      const hash = createHash("sha256");
      hash.update(data.join(""));
      this._key.push(hash.digest("hex"));
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error creating hash:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed to create hash.");
    }
  }

  public get key(): string[] {
    return this._key;
  }

  private getRandomElement(arr: string[]): string {
    if (!arr || arr.length === 0) {
      throw new Error("Array is empty or undefined.");
    }

    try {
      const randomIndex = randomBytes(1)[0] % arr.length;
      return arr[randomIndex];
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error getting random element:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed to get random element.");
    }
  }
}

// import { createHash, randomBytes } from "crypto";
// import { Modul_0, Modul_1, Modul_2, Modul_3 } from "../config/keygen";
// import { getHashedMatrix } from "../config/matrix";

// export class Trust {
//   private _key: string[] = [];
//   private _userKey: string;

//   private readonly SHA_256: string = Modul_0.SHA_256;
//   private readonly AES_256: string = Modul_0.AES_256;
//   private readonly UUI_128: string = Modul_0.UUI_128;

//   private readonly SALT_256: string = Modul_1.SALT_256;
//   private readonly SALT_MIX: string = Modul_1.SALT_MIX;

//   private readonly METRIC: string[] = Modul_2.METRIC;

//   private readonly JTRACK: string = Modul_3.JTRACK;
//   private readonly DB_KEY: string[] = Modul_3.DB_KEY;
//   private readonly VIM_UUI: string[] = Modul_3.VIM_UUI;

//   private readonly HASHED_MATRIX: string[] = getHashedMatrix();

//   constructor(userKey: string) {
//     this._userKey = userKey;
//     this.logical();
//   }

//   private logical(): void {
//     const _SHA_256 = this.SHA_256.substring(0, 29);
//     const _AES_256 = this.AES_256.slice(-19);
//     const _UUI_128 = this.UUI_128;

//     const _SALT_256 = this.SALT_256;
//     const _SALT_MIX = this.SALT_MIX.slice(-15);

//     const _METRIC = this.getRandomElement(this.METRIC);

//     const _JTRACK = this.JTRACK.substring(8, 21);

//     const _DB_KEY = this.getRandomElement(this.DB_KEY);

//     const _VIM_UUI = this.getRandomElement(this.VIM_UUI);

//     const _HASHED_MATRIX = this.HASHED_MATRIX;

//     // Генериране на криптографски сигурен произволен salt
//     const randomSalt = randomBytes(16).toString("hex");

//     // Включване на hash на всяко matrix
//     _HASHED_MATRIX.forEach((matrix) => {
//       this.createHash([matrix, randomSalt]);
//     });

//     // Създаване на финален hash с включване на randomSalt и userKey
//     this.createHash([
//       _SHA_256,
//       _AES_256,
//       _UUI_128,
//       _SALT_256,
//       _SALT_MIX,
//       _METRIC,
//       _JTRACK,
//       _DB_KEY,
//       _VIM_UUI,
//       this._userKey,
//       randomSalt,
//     ]);
//   }

//   private createHash(data: string[]): void {
//     this._key.push(createHash("sha256").update(data.join("")).digest("hex"));
//   }

//   public get key(): string[] {
//     return this._key;
//   }

//   private getRandomElement(arr: string[]): string {
//     const randomIndex = randomBytes(1)[0] % arr.length;
//     return arr[randomIndex];
//   }
// }

// // import { createHash } from "crypto";
// // import { Modul_0, Modul_1, Modul_2, Modul_3 } from "../config/keygen";
// // import { getHashedMatrix } from "../config/matrix";

// // export class Trust {
// //   private _key: string[] = [];
// //   private _userKey: string;

// //   private readonly SHA_256: string = Modul_0.SHA_256;
// //   private readonly AES_256: string = Modul_0.AES_256;
// //   private readonly UUI_128: string = Modul_0.UUI_128;

// //   private readonly SALT_256: string = Modul_1.SALT_256;
// //   private readonly SALT_MIX: string = Modul_1.SALT_MIX;

// //   private readonly METRIC: string[] = Modul_2.METRIC;

// //   private readonly JTRACK: string = Modul_3.JTRACK;
// //   private readonly DB_KEY: string[] = Modul_3.DB_KEY;
// //   private readonly VIM_UUI: string[] = Modul_3.VIM_UUI;

// //   private readonly HASHED_MATRIX: string[] = getHashedMatrix();

// //   constructor(userKey: string) {
// //     this._userKey = userKey;
// //     this.logical();
// //   }

// //   private logical(): void {
// //     const _SHA_256 = this.SHA_256.substring(0, 29);
// //     const _AES_256 = this.AES_256.slice(-19);
// //     const _UUI_128 = this.UUI_128;

// //     const _SALT_256 = this.SALT_256;
// //     const _SALT_MIX = this.SALT_MIX.slice(-15);

// //     const _METRIC = this.METRIC[Math.floor(Math.random() * this.METRIC.length)];

// //     const _JTRACK = this.JTRACK.substring(8, 21);

// //     const _DB_KEY = this.DB_KEY[Math.floor(Math.random() * this.DB_KEY.length)];

// //     const _VIM_UUI =
// //       this.VIM_UUI[Math.floor(Math.random() * this.VIM_UUI.length)];

// //     const _HASHED_MATRIX = this.HASHED_MATRIX;

// //     _HASHED_MATRIX.forEach((matrix) => {
// //       this.createHash([matrix]);
// //     });

// //     this.createHash([
// //       _SHA_256,
// //       _AES_256,
// //       _UUI_128,
// //       _SALT_256,
// //       _SALT_MIX,
// //       _METRIC,
// //       _JTRACK,
// //       _DB_KEY,
// //       _VIM_UUI,
// //       this._userKey,
// //     ]);
// //   }

// //   private createHash(data: string[]): void {
// //     this._key.push(createHash("sha256").update(data.join("")).digest("hex"));
// //   }

// //   public get key(): string[] {
// //     return this._key;
// //   }
// // }
