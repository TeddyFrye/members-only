require("dotenv").config();
const bcrypt = require("bcrypt");
const saltRounds = 10;
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const PORT = process.env.PORT || 5001;

const app = express();

// Connect to MongoDB
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

mongoose.set("strictQuery", false);
const mongoDB = process.env.MONGODB_URL;

async function main() {
  await mongoose.connect(mongoDB, {});
  console.log("Connected to MongoDB");
}
main().catch((err) => console.log(err));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    membershipStatus: { type: String, required: true },
  })
);

const Post = mongoose.model(
  "Post",
  new Schema({
    author: { type: Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  })
);

app.set("views", __dirname);
app.set("view engine", "ejs");
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).lean();
    done(null, user);
  } catch (err) {
    done(err);
  }
});
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", async (req, res) => {
  try {
    const users = await User.find();
    const posts = await Post.find().select("-author -createdAt").lean();

    res.render("index", { users: users, user: req.user || null, posts: posts });
  } catch (error) {
    console.error("Failed to fetch data:", error);

    res.status(500).render("index", { user: req.user || null, posts: [] });
  }
});

app.get("/signup", (req, res) => res.render("routes/sign-up-form"));
app.post("/signup", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
    const requiredPasscode = "PLEASE";
    if (req.body.membershipPasscode !== requiredPasscode) {
      return res.status(403).send("Incorrect Membership Passcode");
    }
    const user = new User({
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      membershipStatus: req.body.membershipStatus,
    });

    await user.save();
    res.redirect("/");
  } catch (err) {
    console.error("Signup error:", err);
    next(err);
  }
});

app.get("/log-in", (req, res) => {
  if (req.user) {
    res.redirect("/");
  } else {
    res.render("log-in");
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/forum", async (req, res) => {
  if (!req.user) {
    res.redirect("/login");
  } else {
    const posts = await Post.find().populate("author", "username");
    res.render("forum", { posts: posts, user: req.user });
  }
});

app.post("/forum", async (req, res) => {
  if (!req.user) {
    res.redirect("login");
  } else {
    const post = new Post({
      content: req.body.content,
      author: req.user._id,
    });

    await post.save();
    res.redirect("forum");
  }
});

app.get("/confirm-delete/:postId", async (req, res) => {
  if (!req.user || req.user.membershipStatus !== "admin") {
    return res.status(403).send("Forbidden");
  }

  const postId = req.params.postId;
  res.render("confirm-delete", { postId: postId });
});

app.post("/delete-post/:postId", async (req, res) => {
  if (!req.user || req.user.membershipStatus !== "admin") {
    res.status(403).send("Forbidden");
  } else {
    await Post.findByIdAndDelete(req.params.postId);
    res.redirect("/forum");
  }
});

app.listen(5001, () => console.log("app listening on port 5001!"));
