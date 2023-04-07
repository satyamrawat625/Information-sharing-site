//jshint esversion:6
require("dotenv").config()
const express = require("express")
const bodyParser = require("body-parser");
const ejs = require("ejs")
const app = express();
const mongoose = require("mongoose")

const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate = require("mongoose-findorcreate")
app.set("view engine", 'ejs')//tells our app to use ejs as view engine
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use(session({//tell app to use session package 
  secret: "our little secret.",//set initial confign
  resave: false,
  saveUninitialized: false
}))

app.use(passport.initialize())// tell app to use passport & initialize smae package
app.use(passport.session())// tell app to use passport to deal with sessions

mongoose.set('strictQuery', false)

mongoose.connect(process.env.URL, { useNewUrlParser: true })

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,//if the user registered using google id
  secret: String
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
  res.render("home")
})

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }));//tell google that we want user's profile

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secret page.
    res.redirect("/secrets");
  });

app.get("/login", function (req, res) {
  res.render("login", { failedAttempt: false })
})

app.get("/register", function (req, res) {
  res.render("register",{failedRegAttempt:false})
})

app.get("/logout", function (req, res) {
  req.logOut(function (err) {
    if (err) {
      console.log(err);
      return res.send(err)
    }
  })
  res.redirect("/")
})

app.get("/secrets", function (req, res) {
  User.find({ "secret": { $ne: null } }, function (err, foundUser) {
    if (err) console.log(err);
    else {
      if (foundUser) res.render("secrets", { usersWithSecrets: foundUser })
    }
  })
})

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit")
  }
  else res.redirect("/login")
})

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret

  User.findById(req.user.id, function (err, foundUser) {
    if (err) console.log(err);
    else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save()
        res.redirect("/secrets")
      }
    }
  })
})

app.post("/register", function (req, res) {
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      // console.log(err);
      res.render("register",{failedRegAttempt:true})
    }
    else passport.authenticate("local")(req, res, function () {
      res.redirect("/secrets")
    })
  })
})

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  })

      passport.authenticate("local", function (err, user, info) {
        if (err) {
          console.log(err);
          return res.render("login",{failedAttempt:true});
        }
        else if (!user) {
          return res.render("login",{failedAttempt:true});
        }

        req.logIn(user, function (err) {
          if (err) {
            // console.log(err);
            return res.redirect("/login");
          }
          return res.redirect("/secrets");
        });
      })(req, res);
})

app.listen(3000, function () {
  console.log("Server started on port 3000");
})


