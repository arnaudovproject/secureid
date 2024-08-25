import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import { createHash } from "crypto";
import { Modul_3 } from "../config/keygen";

export class Helper {
  private secure: boolean;
  private readonly JTRACK: string = Modul_3.JTRACK;

  constructor(secure: boolean) {
    if (typeof secure !== "boolean") {
      throw new Error("Invalid input: 'secure' must be a boolean value.");
    }

    this.secure = secure;
  }

  private cryptSessionName(): string {
    try {
      if (!this.JTRACK || this.JTRACK.length === 0) {
        throw new Error("Invalid JTRACK value.");
      }

      const hash = createHash("sha256");
      hash.update(this.JTRACK);
      return hash.digest("hex");
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error in cryptSessionName:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed to generate session name.");
    }
  }

  public createCookie<T extends string>(data: T): string {
    try {
      if (typeof data !== "string" || data.length === 0) {
        throw new Error(
          "Invalid data: Cookie data must be a non-empty string."
        );
      }

      const cookieOptions = {
        httpOnly: true,
        secure: this.secure,
        sameSite: "strict" as const,
        maxAge: 3600000, // 1 hour in milliseconds
      };

      const cookieData = serializeCookie(
        this.cryptSessionName(),
        data,
        cookieOptions
      );

      return cookieData;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error in createCookie:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed to create cookie.");
    }
  }

  public getCookieName(): string {
    try {
      return this.cryptSessionName();
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("Error in getCookieName:", error.message);
      } else {
        console.error("Unexpected error:", error);
      }
      throw new Error("Failed to retrieve cookie name.");
    }
  }
}

// import { parse as parseCookie, serialize as serializeCookie } from "cookie";
// import { createHash } from "crypto";
// import { Modul_3 } from "../config/keygen";

// export class Helper {
//   private secure: boolean;
//   private readonly JTRACK: string = Modul_3.JTRACK;

//   constructor(secure: boolean) {
//     this.secure = secure;
//   }

//   private cryptSessionName(): string {
//     const _JTRACK = this.JTRACK;

//     const hash = createHash("sha256");
//     hash.update(_JTRACK);
//     return hash.digest("hex");
//   }

//   public createCookie<T extends string>(data: T): string {
//     const cookieOptions = {
//       httpOnly: true,
//       secure: this.secure,
//       sameSite: "strict" as const,
//       maxAge: 3600000,
//     };

//     const cookieData = serializeCookie(
//       this.cryptSessionName(),
//       data,
//       cookieOptions
//     );

//     return cookieData;
//   }

//   public getCookieName(): string {
//     return this.cryptSessionName();
//   }
// }
