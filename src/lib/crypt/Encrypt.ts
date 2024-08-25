import crypto from "crypto";
import { Trust } from "../utility/Trust";

export class Encrypt {
  private trust: Trust;
  private encryptData: object = {};

  private algorithm: string = "aes-256-gcm";
  private key: Buffer;
  private iv: Buffer = crypto.randomBytes(12);

  constructor(password: string) {
    try {
      if (!password || password.length === 0) {
        throw new Error("Password cannot be empty.");
      }

      this.trust = new Trust(password);
      this.key = crypto.scryptSync(password, this.trust.key[0], 32);
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error during encryption initialization:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Encryption initialization failed.");
    }
  }

  private crypt(): crypto.Cipher {
    try {
      return crypto.createCipheriv(this.algorithm, this.key, this.iv);
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error creating cipher:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed to create cipher.");
    }
  }

  private encrypt<T>(data: T) {
    try {
      const cipher = this.crypt();
      const _data = JSON.stringify(data);

      let encrypted = cipher.update(_data, "utf8", "hex");
      encrypted += cipher.final("hex");

      const tag = (cipher as crypto.CipherGCM).getAuthTag().toString("hex");

      this.encryptData = {
        encryptedData: encrypted,
        tag,
        iv: this.iv.toString("hex"),
      };
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error during encryption:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Data encryption failed.");
    }
  }

  set data(data: any) {
    try {
      if (data == null || typeof data !== "object") {
        throw new Error("Data must be a non-null object.");
      }

      this.encrypt(data);
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error setting data:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Invalid data for encryption.");
    }
  }

  get encryptedData(): object {
    return this.encryptData;
  }
}

// import crypto from "crypto";
// import { Trust } from "../utility/Trust";

// export class Encrypt {
//   private trust: Trust;
//   private encryptData: object = {};

//   private algorithm: string = "aes-256-gcm";
//   private key: Buffer;
//   private iv: Buffer = crypto.randomBytes(12);

//   constructor(password: string) {
//     this.trust = new Trust(password);
//     this.key = crypto.scryptSync(password, this.trust.key[0], 32);
//   }

//   private crypt(): crypto.Cipher {
//     return crypto.createCipheriv(this.algorithm, this.key, this.iv);
//   }

//   private encrypt<T>(data: T) {
//     const cipher = this.crypt();
//     const _data = JSON.stringify(data);
//     let encrypted = cipher.update(_data, "utf8", "hex");
//     encrypted += cipher.final("hex");
//     const tag = (cipher as crypto.CipherGCM).getAuthTag().toString("hex");

//     this.encryptData = {
//       encryptedData: encrypted,
//       tag,
//       iv: this.iv.toString("hex"),
//     };
//   }

//   set data(data: any) {
//     this.encrypt(data);
//   }

//   get encryptedData(): object {
//     return this.encryptData;
//   }
// }
