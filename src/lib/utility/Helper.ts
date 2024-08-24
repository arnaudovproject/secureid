import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import { createHash } from "crypto";
import { Modul_3 } from "../config/keygen";
import { HttpRequest } from "../interfaces/HttpRequestInterface";

export class Helper {
  private secure: boolean;
  private readonly JTRACK: string = Modul_3.JTRACK;

  constructor(secure: boolean) {
    this.secure = secure;
  }

  private cryptSessionName(): string {
    const _JTRACK = this.JTRACK;

    const hash = createHash("sha256");
    hash.update(_JTRACK);
    return hash.digest("hex");
  }

  public createCookie<T extends string>(
    data: T,
    res: { setHeader: (name: string, value: string) => void }
  ): void {
    const cookieOptions = {
      httpOnly: true,
      secure: this.secure,
      sameSite: "strict" as const,
      maxAge: 3600000,
    };

    const cookieData = serializeCookie(
      this.cryptSessionName(),
      data,
      cookieOptions
    );

    res.setHeader("Set-Cookie", cookieData);
  }

  public checkCookieExists(req: HttpRequest): boolean {
    const cookies = parseCookie(req.getHeader("Cookie") || "");
    const sessionName = this.cryptSessionName();
    return cookies.hasOwnProperty(sessionName);
  }
}
