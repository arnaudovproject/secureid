import { Encrypt } from "./crypt/Encrypt";
import { Decrypt } from "./crypt/Decrypt";
import { Helper } from "./utility/Helper";

export class Secure {
  private static cryptInstance<T>(password: string, data: T): object | null {
    try {
      const encryptor = new Encrypt(password);
      encryptor.data = data;
      return encryptor.encryptedData;
    } catch (error) {
      console.error("Error creating instance:", error);
      return null;
    }
  }

  private static decryptInstance<T>(
    encryptedData: string,
    tag: string,
    iv: string,
    password: string
  ): T | null {
    try {
      const decryptor = new Decrypt(encryptedData, tag, iv, password);
      return decryptor.getData<T>();
    } catch (error) {
      console.error("Error decrypting instance:", error);
      return null;
    }
  }

  public static bind<T>(
    password: string,
    data: T,
    {
      secure,
    }: {
      secure: boolean;
    }
  ) {
    const encrypted = Secure.cryptInstance(password, data);

    if (encrypted) {
      const { encryptedData, tag, iv } = encrypted as {
        encryptedData: string;
        tag: string;
        iv: string;
      };

      const secureHelper = new Helper(secure);

      const serializedData = JSON.stringify({ encryptedData, tag, iv });

      return secureHelper.createCookie(serializedData);
    }
  }

  public static cookieName(): string {
    const secureHelper = new Helper(false);
    const cookieNmae = secureHelper.getCookieName();
    return cookieNmae;
  }

  public static unBind<T>(cookieValue: T, password: string) {
    const cookieData = JSON.parse(cookieValue as string);
    const { encryptedData, tag, iv } = cookieData;

    return Secure.decryptInstance<T>(encryptedData, tag, iv, password);
  }
}
