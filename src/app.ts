import express from "express";
import { PrismaClient, User } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { createHash, randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import config from "./config";

const app: express.Express = express();

const PORT = Number(config.port ?? 3000);

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL!,
});

const prisma = new PrismaClient({
  adapter,
});

app.use(express.json());


// ========================================
// JWTトークン確認
// ========================================
async function VerifyToken(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> {

  const authHeader = req.headers["authorization"];

  if (authHeader !== undefined) {

    if (authHeader.split(" ")[0] === "Bearer") {

      try {

        const token = jwt.verify(
          authHeader.split(" ")[1],
          config.jwt_secret || ""
        ) as jwt.JwtPayload;

        const result = await prisma.user.findFirst({
          where: {
            name: token.name as string,
          },
        });

        if (
          result != null &&
          token.exp &&
          Date.now() < token.exp * 1000
        ) {

          console.log(token);

          next();
          return;

        } else {

          res.json({
            error: "Auth error",
          });

          return;
        }

      } catch (e: any) {

        console.log(e.message);

        res.json({
          error: e.message,
        });

        return;
      }

    } else {

      res.json({
        error: "header format error",
      });

      return;
    }

  } else {

    res.json({
      error: "header error",
    });

    return;
  }
}


// ========================================
// JWTからログインユーザーを取得
// ========================================
async function GetUser(
  req: express.Request
): Promise<User | {}> {

  const authHeader = req.headers["authorization"];

  if (authHeader !== undefined) {

    if (authHeader.split(" ")[0] === "Bearer") {

      try {

        const token = jwt.verify(
          authHeader.split(" ")[1],
          config.jwt_secret || ""
        ) as jwt.JwtPayload;

        const result = await prisma.user.findFirst({
          where: {
            name: token.name as string,
          },
        });

        if (
          result != null &&
          token.exp &&
          Date.now() < token.exp * 1000
        ) {

          return result;
        }

      } catch (e: any) {

        console.log(e.message);
      }
    }
  }

  return {};
}


// ========================================
// スコア一覧取得
// JWT認証後、高い順に5件取得
// Userテーブルの情報も一緒に取得
// ========================================
app.get(
  "/scores",
  VerifyToken,
  async (
    req: express.Request,
    res: express.Response
  ): Promise<void> => {

    try {

      const scores = await prisma.score.findMany({

        orderBy: [
          {
            score: "desc",
          },
        ],

        include: {
          user: true,
        },

        take: 5,
      });

      res.json(scores);

    } catch (error) {

      console.error("DBエラー:", error);

      res.status(500).json({
        status_code: 500,
        message: "DBエラー",
      });
    }
  }
);


// ========================================
// スコア登録
// JWTからユーザーIDを取得してScoreと関連付ける
// ========================================
app.post(
  "/scores",
  VerifyToken,
  async (
    req: express.Request,
    res: express.Response
  ): Promise<void> => {

    const { score } = req.body;

    try {

      const user: any = await GetUser(req);

      const result = await prisma.score.create({
        data: {
          userId: user.id,
          score: score,
        },
      });

      if (result != null) {

        res.json({
          status_code: 200,
        });

        return;

      } else {

        res.json({
          status_code: 500,
        });

        return;
      }

    } catch (error) {

      console.error("DBエラー:", error);

      res.status(500).json({
        status_code: 500,
        message: "DBエラー",
      });
    }
  }
);


// ========================================
// ユーザー新規作成
// Salt + Pepperでパスワードをハッシュ化
// ========================================
app.post(
  "/users/new",
  async (
    req: express.Request,
    res: express.Response
  ): Promise<void> => {

    const name = req.body.name;

    // Saltをランダム生成
    const salt = randomBytes(8).toString("hex");

    // password + salt + pepper をSHA256でハッシュ化
    const password = createHash("sha256")
      .update(
        req.body.password +
        salt +
        (config.pepper || ""),
        "utf8"
      )
      .digest("hex");

    try {

      const result = await prisma.user.create({
        data: {
          name,
          password,
          salt,
        },
      });

      res.json(result);

    } catch (error) {

      console.error("DBエラー:", error);

      res.status(500).json({
        status_code: 500,
        message: "DBエラー",
      });
    }
  }
);


// ========================================
// ログイン
// 成功したらJWTを返す
// 有効期限は1時間
// ========================================
app.post(
  "/users/login",
  async (
    req: express.Request,
    res: express.Response
  ): Promise<void> => {

    const name = req.body.name;

    try {

      // ユーザー名からSaltを取得
      const saltres = await prisma.user.findFirst({
        where: {
          name: name,
        },
      });

      if (saltres != null) {

        const salt = saltres.salt;

        // 入力されたパスワードを
        // Salt + Pepper付きでハッシュ化
        const password = createHash("sha256")
          .update(
            req.body.password +
            salt +
            (config.pepper || ""),
            "utf8"
          )
          .digest("hex");

        // ユーザー名とハッシュ化パスワードで検索
        const result = await prisma.user.findFirst({
          where: {
            name: name,
            password: password,
          },
        });

        if (result != null) {

          // JWT生成
          const token = jwt.sign(
            {
              name: name,
            },
            config.jwt_secret || "",
            {
              expiresIn: "1h",
            }
          );

          res.json({
            login_status: "success",
            token: token,
          });

          return;

        } else {

          res.json({
            login_status: "failed",
          });

          return;
        }

      } else {

        res.json({
          login_status: "No User found.",
        });

        return;
      }

    } catch (error) {

      console.error("DBエラー:", error);

      res.status(500).json({
        login_status: "failed",
      });
    }
  }
);


// ========================================
// サーバー起動
// ========================================
app.listen(PORT, () => {

  console.log(
    "Server is running on PORT:",
    PORT
  );
});
