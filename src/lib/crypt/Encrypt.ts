import crypto from "crypto";
import { Trust } from "../utility/Trust";

export class Encrypt {
  private trust: Trust;
  private encryptData: object = {};

  private algorithm: string = "aes-256-gcm";
  private key: Buffer;
  private iv: Buffer = crypto.randomBytes(12);

  constructor(password: string) {
    this.trust = new Trust(password);
    this.key = crypto.scryptSync(password, this.trust.key[0], 32);
  }

  private crypt(): crypto.Cipher {
    return crypto.createCipheriv(this.algorithm, this.key, this.iv);
  }

  private encrypt<T>(data: T) {
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
  }

  set data(data: any) {
    this.encrypt(data);
  }

  get encryptedData(): object {
    return this.encryptData;
  }
}
