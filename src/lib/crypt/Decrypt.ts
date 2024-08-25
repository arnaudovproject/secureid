import crypto from "crypto";
import { Trust } from "../utility/Trust";

export class Decrypt {
  private trust: Trust;
  private algorithm: string = "aes-256-gcm";
  private key: Buffer;
  private iv: Buffer;
  private tag: Buffer;
  private encryptedData: string;

  constructor(
    encryptedData: string,
    tag: string,
    iv: string,
    password: string
  ) {
    try {
      if (!password || password.length === 0) {
        throw new Error("Password cannot be empty.");
      }

      if (!encryptedData || !tag || !iv) {
        throw new Error("Invalid input data for decryption.");
      }

      this.trust = new Trust(password);
      this.encryptedData = encryptedData;
      this.tag = Buffer.from(tag, "hex");
      this.iv = Buffer.from(iv, "hex");
      this.key = crypto.scryptSync(password, this.trust.key[0], 32);
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error during decryption initialization:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Decryption initialization failed.");
    }
  }

  private decrypt(): string {
    try {
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        this.key,
        this.iv
      ) as crypto.DecipherGCM;
      decipher.setAuthTag(this.tag);

      let decrypted = decipher.update(this.encryptedData, "hex", "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error during decryption:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Data decryption failed. Possible tampering detected.");
    }
  }

  public getData<T>(): T {
    try {
      const decryptedData = this.decrypt();
      return JSON.parse(decryptedData) as T;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error parsing decrypted data:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed to parse decrypted data.");
    }
  }
}

// import crypto from "crypto";
// import { Trust } from "../utility/Trust";

// export class Decrypt {
//   private trust: Trust;
//   private algorithm: string = "aes-256-gcm";
//   private key: Buffer;
//   private iv: Buffer;
//   private tag: Buffer;
//   private encryptedData: string;

//   constructor(
//     encryptedData: string,
//     tag: string,
//     iv: string,
//     password: string
//   ) {
//     this.trust = new Trust(password);
//     this.encryptedData = encryptedData;
//     this.tag = Buffer.from(tag, "hex");
//     this.iv = Buffer.from(iv, "hex");
//     this.key = crypto.scryptSync(password, this.trust.key[0], 32);
//   }

//   private decrypt(): string {
//     const decipher = crypto.createDecipheriv(
//       this.algorithm,
//       this.key,
//       this.iv
//     ) as crypto.DecipherGCM;
//     decipher.setAuthTag(this.tag);
//     let decrypted = decipher.update(this.encryptedData, "hex", "utf8");
//     decrypted += decipher.final("utf8");
//     return decrypted;
//   }

//   public getData<T>(): T {
//     const decryptedData = this.decrypt();
//     return JSON.parse(decryptedData) as T;
//   }
// }
