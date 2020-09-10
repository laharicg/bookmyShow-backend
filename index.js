const express = require("express");
const bodyParser = require("body-parser");
require("dotenv").config();
const mongodb = require("mongodb");
const cors = require("cors");
const bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post("/login", async (req, res) => {
  var user = req.body;
  try {
    const client = await mongodb.connect(process.env.DBURL);
    const db = client.db("BMS");
    var data = await db.collection("users").findOne({ email: user.email });
    if (data === null) {
      res.status(404).json({ message: "User does not exists" });
      return;
    }
    const result = await bcrypt.compare(user.password, data.password);
    if (result) {
      delete data.password;
      let jwtToken = jwt.sign({ user: data }, process.env.JWTTK, {
        expiresIn: "365d",
      });
      res.json({ message: "success", user: data, jwtToken: jwtToken });
    } else {
      res.json({ message: "Password not matching" });
    }
  } catch (err) {
    console.log(err);
    res.json({ message: "failed" });
    return;
  }
});

app.post("/register", async (req, res) => {
  var user = req.body;
  user.permission = "none";
  user.isEmailVerified = false;
  try {
    const client = await mongodb.connect(process.env.DBURL);
    const db = client.db("BMS");
    const data = await db
      .collection("users")
      .findOne({ email: user.email }, { name: 1 });
    console.log(data);
    if (data !== null) {
      res.json({ message: "User already exists" });
      return;
    }
  } catch (err) {
    console.log(err);
    res.json({ message: "failed" });
    return;
  }
  var hash = await bcrypt.hash(user.password, 10);
  user.password = hash;
  try {
    const client = await mongodb.connect(process.env.DBURL);
    const db = client.db("BMS");
    const data = await db.collection("users").insertOne(user);
    await client.close();
    res.json({ message: "success" });
  } catch (err) {
    console.log(err);
    res.json({ message: "failed" });
  }
});

function authorize(req, res, next) {
  try {
    if (req.headers.auth !== undefined) {
      let jwtmessage = jwt.verify(req.headers.auth, process.env.JWTTK);
      res.locals.user = jwtmessage.user;
      next();
    } else {
      res.status(404).json({ message: "authorization failed" });
    }
  } catch (err) {
    console.log(err);
    res.status(404).json({ message: "authorization failed" });
  }
}

app.get("/dashboard", [authorize], async (req, res) => {
  var user = req.body;
  try {
    // do something ....
    const client = await mongodb.connect(process.env.DBURL);
    const db = client.db("BMS");
    var [theatres, movies] = await Promise.all([
      db.collection("theatres").find().toArray(),
      db.collection("movies").find().toArray(),
    ]);
    console.log(theatres.length, movies.length);

    res.json({ message: "success", theatres, movies });
  } catch (err) {}
});

app.post("/access", [authorize], async (req, res) => {
  console.log(req.body);
  try {
    // do something ....
    const client = await mongodb.connect(process.env.DBURL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    const db = client.db("BMS");
    var data = await db
      .collection("users")
      .findOne({ email: res.locals.user.email });
    if (data.access === "admin" && data.permission === "grant") {
      // res.json({message : 'dashboard' , user : res.locals.user })
      var users = await db
        .collection("users")
        .updateOne(
          { _id: mongodb.ObjectID(req.body._id) },
          { $set: { permission: req.body.permission } }
        );

      res.json({ message: "success", users: users });
    } else {
      res.status(404).json({ message: "Access Denied" });
    }
  } catch (err) {
    console.log(err);
    res.status(404).json({ message: "failed" });
  }
});

app.get("/access", [authorize], async (req, res) => {
  try {
    // do something ....
    const client = await mongodb.connect(process.env.DBURL);
    const db = client.db("BMS");
    var data = await db
      .collection("users")
      .findOne({ email: res.locals.user.email });
    console.log(data);
    if (
      (data.access === "theatreowner" || data.access === "admin") &&
      (data.permission === "view" || data.permission === "grant")
    ) {
      // res.json({message : 'dashboard' , user : res.locals.user })
      var users = await db
        .collection("users")
        .find({ access: { $not: /^admin/ } }, { password: 0 })
        .toArray();
      users = users.filter((user) => user.email !== data.email);
      res.json({ message: "success", users: users });
      await client.close();
    } else {
      res.status(404).json({ message: "You do not have permission to view" });
      await client.close();
    }
  } catch (err) {
    res.status(404).json({ message: "failed" });
  }
});

app.listen(process.env.PORT || 5000, () => {
  console.log("Listening .... ");
});
