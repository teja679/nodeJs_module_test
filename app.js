const express = require("express");
const validator = require("validator");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const UserSchema = require("./UserSchema");
const app = express();

const { cleanUpAndValidate } = require("./Utils/AuthUtils");

app.set("view engine", "ejs");

mongoose.set("strictQuery", false);
const mongoURI = `mongodb+srv://teja110:teja12345@cluster0.mdeyr12.mongodb.net/teja110`;
mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then((res) => {
    console.log("connect DB");
  })
  .catch((err) => {
    console.log(err);
  });

//   const store = new mongoDBSession({
//     uri: mongoURI,
//     collection: "sessions",
//   });
  
//   app.use(
//     session({
//       secret: "hello backendjs",
//       resave: false,
//       saveUninitialized: false,
//       store: store,
//     })
//   );

//middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send("Welcome to my app");
});

app.get("/login", (req, res) => {
  return res.render("login");
});

app.get("/register", (req, res) => {
 return res.render("register");
});

app.get("/dashboard", (req, res) => {
    return res.render("dashboard");
   });
   
// ------------------- REGISTER --------------------
app.post("/register", async (req, res) => {
    console.log(req.body);
    const { name, username, password, email } = req.body;
    try {
      await cleanUpAndValidate({ name, username, password, email });
    } catch (err) {
      return res.send({
        status: 400,
        message: err,
      });
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);
  
    console.log(hashedPassword)

    let user = new UserSchema({
      name: name,
      password: hashedPassword,
      email: email,
      username: username,
    });
  
    let userExists;
    // check if user already exists
  
    try {
      userExists = await UserSchema.findOne({ email });
    } catch (err) {
      return res.send({
        status: 400,
        message: "Internal Server Error. Please try again.",
        // error: err,
      });
    }
    if (userExists) {
      return res.send({
        status: 400,
        message: "User with email already exists.",
      });
    }
  
    try {
      const userDB = await user.save(); // create opt in database
      console.log("userDB", userDB);
      return res.redirect("login");
    //   res.send({
    //     status: 201,
    //     message: "Registered successfully",
    //     data: {
    //       _id: userDB._id,
    //       username: userDB.username,
    //       email: userDB.email,
    //     },
    //   });
    } catch (err) {
      return res.send({
        status: 400,
        message: "Internal server Error, please try again",
        // error: err,
      });
    }
  });

  app.post("/login", async (req, res) => {
    // loginId can be either email or username
    console.log(req.body);
    const { loginId, password } = req.body;
    if (
      typeof loginId !== "string" ||
      typeof password !== "string" ||
      !loginId ||
      !password
    ) {
      return res.send({
        status: 400,
        message: "Invalid Data",
      });
    }
  
    //find() - May return you multiple objects, Returns empty array if nothing matches, returns an array of objects
    //findOne() - One object, Returns null if nothing matches, returns an object
    let userDb;
    try {
      if (validator.isEmail(loginId)) {
        userDb = await UserSchema.findOne({ email: loginId });
      } else {
        userDb = await UserSchema.findOne({ username: loginId });
      }
    } catch (err) {
      console.log(err);
      return res.send({
        status: 400,
        message: "Internal server error. Please try again",
        // error: err,
      });
    }
  
    console.log(userDb);
  
    if (!userDb) {
      return res.send({
        status: 400,
        message: "user not found",
        data: req.body,
      });
    }
  
    // comparing the password
    const isMatch = await bcrypt.compare(password, userDb.password);
  
    if (!isMatch) {
      return res.send({
        status: 400,
        message: "Invalid password",
        error: req.body,
      });
    }
    //include session info to check further
    // req.session.isAuth = true;
    // req.session.user = {
    //   username: userDb.username,
    //   email: userDb.email,
    //   userId: userDb._id,
    // };
    res.redirect("/dashboard");
  });
app.listen(4000, () => {
  console.log("Listening on port 4000");
});
