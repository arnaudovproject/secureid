import { Encrypt } from "./crypt/Encrypt";
import { Decrypt } from "./crypt/Decrypt";
import { Helper } from "./utility/Helper";
import { HttpRequest } from "./interfaces/HttpRequestInterface";

export class Secure {
  private static createInstance<T>(password: string, data: T): object | null {
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

  public static bindSecure<T>(
    password: string,
    data: T,
    {
      secure,
      response,
    }: {
      secure: boolean;
      response: { setHeader: (name: string, value: string) => void };
    }
  ) {
    const encrypted = Secure.createInstance(password, data);

    if (encrypted) {
      const { encryptedData, tag, iv } = encrypted as {
        encryptedData: string;
        tag: string;
        iv: string;
      };

      const secureHelper = new Helper(secure);

      const serializedData = JSON.stringify({ encryptedData, tag, iv });

      secureHelper.createCookie(serializedData, response);
    }
  }

  public static cookieExists(req: HttpRequest, secure: boolean): boolean {
    const secureHelper = new Helper(secure);
    return secureHelper.checkCookieExists(req);
  }
}
