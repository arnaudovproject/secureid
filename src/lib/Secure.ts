import { Encrypt } from "./crypt/Encrypt";
import { Decrypt } from "./crypt/Decrypt";
import { Helper } from "./utility/Helper";

export class Secure {
  private static cryptInstance<T>(password: string, data: T): object | null {
    try {
      const encryptor = new Encrypt(password);
      encryptor.data = data;
      return encryptor.encryptedData;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error creating Encrypt instance:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
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
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error creating Decrypt instance:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      return null;
    }
  }

  public static bind<T>(
    password: string,
    data: T,
    { secure }: { secure: boolean }
  ): string | null {
    try {
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
      } else {
        throw new Error("Encryption failed.");
      }
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error in bind method:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      return null;
    }
  }

  public static cookieName(): string {
    try {
      const secureHelper = new Helper(false);
      return secureHelper.getCookieName();
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error in cookieName method:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      return "";
    }
  }

  public static unBind<T>(cookieValue: string, password: string): T | null {
    try {
      const cookieData = JSON.parse(cookieValue);
      const { encryptedData, tag, iv } = cookieData;

      if (
        typeof encryptedData !== "string" ||
        typeof tag !== "string" ||
        typeof iv !== "string"
      ) {
        throw new Error("Invalid cookie data format.");
      }

      return Secure.decryptInstance<T>(encryptedData, tag, iv, password);
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error in unBind method:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      return null;
    }
  }
}

// import { Encrypt } from "./crypt/Encrypt";
// import { Decrypt } from "./crypt/Decrypt";
// import { Helper } from "./utility/Helper";

// export class Secure {
//   private static cryptInstance<T>(password: string, data: T): object | null {
//     try {
//       const encryptor = new Encrypt(password);
//       encryptor.data = data;
//       return encryptor.encryptedData;
//     } catch (error) {
//       console.error("Error creating instance:", error);
//       return null;
//     }
//   }

//   private static decryptInstance<T>(
//     encryptedData: string,
//     tag: string,
//     iv: string,
//     password: string
//   ): T | null {
//     try {
//       const decryptor = new Decrypt(encryptedData, tag, iv, password);
//       return decryptor.getData<T>();
//     } catch (error) {
//       console.error("Error decrypting instance:", error);
//       return null;
//     }
//   }

//   public static bind<T>(
//     password: string,
//     data: T,
//     {
//       secure,
//     }: {
//       secure: boolean;
//     }
//   ) {
//     const encrypted = Secure.cryptInstance(password, data);

//     if (encrypted) {
//       const { encryptedData, tag, iv } = encrypted as {
//         encryptedData: string;
//         tag: string;
//         iv: string;
//       };

//       const secureHelper = new Helper(secure);

//       const serializedData = JSON.stringify({ encryptedData, tag, iv });

//       return secureHelper.createCookie(serializedData);
//     }
//   }

//   public static cookieName(): string {
//     const secureHelper = new Helper(false);
//     const cookieNmae = secureHelper.getCookieName();
//     return cookieNmae;
//   }

//   public static unBind<T>(cookieValue: T, password: string) {
//     const cookieData = JSON.parse(cookieValue as string);
//     const { encryptedData, tag, iv } = cookieData;

//     return Secure.decryptInstance<T>(encryptedData, tag, iv, password);
//   }
// }
