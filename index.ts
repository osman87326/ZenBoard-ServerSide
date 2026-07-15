import "dotenv/config";
import express, { type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
const app = express();
const port = process.env.PORT || 5000;
const uri = process.env.MONGODB_URI as string;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const COOKIE_NAME = "zenboard_token";
const isProd = process.env.NODE_ENV === "production";

app.use((req: Request, res: Response, next: NextFunction) => {
  const csp = [
    "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' http://localhost:* https://localhost:* ws://localhost:* wss://localhost:*",
    "object-src 'none'",
    "base-uri 'self'",
  ].join("; ");

  res.setHeader("Content-Security-Policy", csp);
  next();
});

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

interface JwtPayload {
  id: string;
  email: string;
  name: string;
}

interface AuthRequest extends Request {
  user?: JwtPayload;
}

let isDbConnected = false;

let userCollection: any = null;
let taskCollection: any = null;
let commentCollection: any = null;
let notificationCollection: any = null;

const getParamValue = (value: string | string[] | undefined): string => {
  if (typeof value === "string") {
    return value;
  }

  return value?.[0] ?? "";
};

const verifyToken = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const token = req.cookies?.[COOKIE_NAME];

  if (!token) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: "Forbidden" });
  }
};

const ensureDb = (res: Response): boolean => {
  if (!isDbConnected) {
    res.status(503).json({ message: "Database unavailable" });
    return false;
  }

  return true;
};

app.get("/users", async (_req: Request, res: Response) => {
  if (!ensureDb(res)) return;

  const cursor = userCollection.find({});
  const users = await cursor.toArray();
  res.json(users);
});

async function run(): Promise<void> {
  try {
    await client.connect();

    const database = client.db(process.env.MONGODB_DB || "ZenBoard");
    userCollection = database.collection("users");
    taskCollection = database.collection("tasks");
    commentCollection = database.collection("comments");
    notificationCollection = database.collection("notifications");
    isDbConnected = true;
    console.log("MongoDB connected successfully!");
  } catch (error) {
    console.error("MongoDB connection failed:", error);
  }

  app.post("/api/auth/register", async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existing = await userCollection.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await userCollection.insertOne({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      avatar: "",
      createdAt: new Date(),
    });

    const payload: JwtPayload = {
      id: result.insertedId.toString(),
      email: email.toLowerCase(),
      name,
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

    res
      .cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .status(201)
      .json({ id: result.insertedId, name, email: email.toLowerCase() });
  });

  app.post("/api/auth/login", async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await userCollection.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const payload: JwtPayload = {
      id: user._id.toString(),
      email: user.email,
      name: user.name,
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

    res
      .cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({ id: user._id, name: user.name, email: user.email });
  });

  app.post("/api/auth/logout", (_req: Request, res: Response) => {
    res
      .clearCookie(COOKIE_NAME, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
      })
      .json({ message: "Logged out" });
  });

  app.get("/api/auth/me", verifyToken, async (req: AuthRequest, res: Response) => {
    if (!ensureDb(res)) return;
    const user = await userCollection.findOne(
      { _id: new ObjectId(req.user!.id) },
      { projection: { password: 0 } }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  });

  app.get("/api/tasks", async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const {
      page = "1",
      limit = "8",
      search = "",
      status,
      priority,
      sort = "newest",
    } = req.query as Record<string, string>;

    const pageNum = Math.max(parseInt(page) || 1, 1);
    const limitNum = Math.max(parseInt(limit) || 8, 1);

    const query: Record<string, unknown> = {};

    if (search) {
      query.title = { $regex: search, $options: "i" };
    }
    if (status) {
      query.status = status;
    }
    if (priority) {
      query.priority = priority;
    }

    let sortOption: Record<string, 1 | -1> = { createdAt: -1 };
    if (sort === "oldest") sortOption = { createdAt: 1 };
    if (sort === "priority") sortOption = { priority: -1 };
    if (sort === "dueDate") sortOption = { dueDate: 1 };

    const total = await taskCollection.countDocuments(query);
    const tasks = await taskCollection
      .find(query)
      .sort(sortOption)
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .toArray();

    res.json({
      tasks,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum),
    });
  });

  app.get("/api/tasks/:id", async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const id = getParamValue(req.params.id);

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const task = await taskCollection.findOne({ _id: new ObjectId(id) });

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    res.json(task);
  });

  app.post("/api/tasks", verifyToken, async (req: AuthRequest, res: Response) => {
    if (!ensureDb(res)) return;
    const task = {
      ...req.body,
      status: req.body.status || "todo",
      priority: req.body.priority || "medium",
      owner_email: req.user!.email,
      createdAt: new Date(),
    };

    const result = await taskCollection.insertOne(task);
    res.status(201).json(result);
  });

  app.patch("/api/tasks/:id", verifyToken, async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const id = getParamValue(req.params.id);

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await taskCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: req.body }
    );

    res.json(result);
  });

  app.delete("/api/tasks/:id", verifyToken, async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const id = getParamValue(req.params.id);

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await taskCollection.deleteOne({ _id: new ObjectId(id) });
    res.json(result);
  });

  app.get("/api/comments/:taskId", async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const comments = await commentCollection
      .find({ task_id: req.params.taskId })
      .sort({ createdAt: 1 })
      .toArray();

    res.json(comments);
  });

  app.post("/api/comments", verifyToken, async (req: AuthRequest, res: Response) => {
    if (!ensureDb(res)) return;
    const { task_id, content } = req.body;

    if (!task_id || !content) {
      return res.status(400).json({ message: "task_id and content are required" });
    }

    const comment = {
      task_id,
      content,
      author_email: req.user!.email,
      author_name: req.user!.name,
      createdAt: new Date(),
    };

    const result = await commentCollection.insertOne(comment);
    res.status(201).json(result);
  });

  app.get("/api/notifications", verifyToken, async (req: AuthRequest, res: Response) => {
    if (!ensureDb(res)) return;
    const notifications = await notificationCollection
      .find({ user_email: req.user!.email })
      .sort({ createdAt: -1 })
      .limit(20)
      .toArray();

    res.json(notifications);
  });

  app.patch("/api/notifications/:id", verifyToken, async (req: Request, res: Response) => {
    if (!ensureDb(res)) return;
    const id = getParamValue(req.params.id);

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await notificationCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { read: true } }
    );

    res.json(result);
  });

  app.get("/api/dashboard/stats", verifyToken, async (req: AuthRequest, res: Response) => {
    if (!ensureDb(res)) return;
    const statusAgg = await taskCollection
      .aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }])
      .toArray();

    const priorityAgg = await taskCollection
      .aggregate([{ $group: { _id: "$priority", count: { $sum: 1 } } }])
      .toArray();

    const velocityAgg = await taskCollection
      .aggregate([
        { $match: { status: "done" } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
        { $limit: 14 },
      ])
      .toArray();

    res.json({
      statusDistribution: statusAgg,
      priorityDistribution: priorityAgg,
      velocity: velocityAgg,
    });
  });

  app.get("/.well-known/appspecific/com.chrome.devtools.json", (_req: Request, res: Response) => {
    res.json({});
  });

  app.get("/", (_req: Request, res: Response) => {
    res.send("ZenBoard server is running");
  });

  const server = app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });

  server.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code === "EADDRINUSE") {
      console.error(`Port ${port} is already in use. Please stop the other process or choose a different PORT.`);
    } else {
      console.error("Server error:", error);
    }
  });
}

run().catch((error) => {
  console.error("Server failed to start:", error);
});
