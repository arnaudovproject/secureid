import { createHash } from "crypto";
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

  private readonly HASHED_MATRIX: string[] = getHashedMatrix();

  constructor(userKey: string) {
    this._userKey = userKey;
    this.logical();
  }

  private logical(): void {
    const _SHA_256 = this.SHA_256.substring(0, 29);
    const _AES_256 = this.AES_256.slice(-19);
    const _UUI_128 = this.UUI_128;

    const _SALT_256 = this.SALT_256;
    const _SALT_MIX = this.SALT_MIX.slice(-15);

    const _METRIC = this.METRIC[Math.floor(Math.random() * this.METRIC.length)];

    const _JTRACK = this.JTRACK.substring(8, 21);

    const _DB_KEY = this.DB_KEY[Math.floor(Math.random() * this.DB_KEY.length)];

    const _HASHED_MATRIX = this.HASHED_MATRIX;

    _HASHED_MATRIX.forEach((matrix) => {
      this.createHash([matrix]);
    });

    this.createHash([
      _SHA_256,
      _AES_256,
      _UUI_128,
      _SALT_256,
      _SALT_MIX,
      _METRIC,
      _JTRACK,
      _DB_KEY,
      this._userKey,
    ]);
  }

  private createHash(data: string[]): void {
    this._key.push(createHash("sha256").update(data.join("")).digest("hex"));
  }

  public get key(): string[] {
    return this._key;
  }
}
