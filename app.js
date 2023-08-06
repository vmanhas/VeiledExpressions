require('dotenv').config()
const express = require('express')
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const saltRounds = 10;
const session = require('express-session')
const passport = require('passport')
const LocalStrategy=require("passport-local").Strategy;
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var findOrCreate = require('mongoose-findorcreate');
 
//init app & middleware
const app = express()
app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({extended:true}))
 
app.use(session({
    secret: 'my secret', 
    resave: false, 
    saveUninitialized: true 
  }));
app.use(passport.initialize());
app.use(passport.session());
 
//DATABASE
mongoose.connect('mongodb://127.0.0.1:27017/userDB');
 
const userSchema = mongoose.Schema({
    username: String,
    password: String,
    googleId:String,
    secret:String
})
userSchema.plugin(findOrCreate);
const User = mongoose.model('User', userSchema)
 
//configure passport local strategy
passport.use(new LocalStrategy(
    function(username, password, done) {
      User.findOne({ username: username })
      .then((founduser)=>{
        if(!founduser){return done(null, false);}
 
        bcrypt.compare(password,founduser.password, (err, result) => {
            if (err){return done(err);}
            if (result) {return done(null,founduser);}
            return done (null,false);
        });
      })
      .catch((err)=>{
        return done(err);
      })
    }
));
 
passport.serializeUser((user,done)=>{
    done(null, user.id)
})
 
passport.deserializeUser((id,done)=>{
    User.findById(id)
    .then((founduser)=>{
        done(null,founduser)
    })
    .catch(err=>{
        done(err)
    })
})
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
 
//ROUTES----------------------------------------------------------------------------------------
//HOME
app.route('/')
    .get((req,res)=>{
        res.render('home')
    })

app.get("/auth/google",
    passport.authenticate("google", { scope: ['profile', 'email'] })
);
 
app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login"}),
    (req, res) => {
        res.redirect("/secrets");
    }
);    
//REGISTER
app.route('/register')
    .get((req,res)=>{
        res.render('register')
    })
    .post((req,res)=>{
        
        bcrypt.hash(req.body.password, saltRounds, (err,hash)=>{
            
            if(err){
                console.log(err)
 
            } else {
                const newUser = new User({
                    username: req.body.username,
                    password: hash
                })
                newUser.save()
                .then(()=>{
                    passport.authenticate('local', {
                        successRedirect: '/secrets',
                        failureRedirect: '/login'
                      })(req, res);
                })
            }
          })
    })
 
//LOGIN
app.route('/login')
    .get((req,res)=>{
        res.render('login')
    })
    .post((req,res)=>{
      
        const user = new User({
            username: req.body.useername,
            password: req.body.password
        })
      
      req.login(user, (err)=>{
        if(err){
            console.log(err)
        } else {
            passport.authenticate('local',{
                successRedirect: '/secrets'
              })(req, res);
        }
      })
    })
 
//SECRETS
app.route('/secrets')
    .get((req,res)=>{
        User.find({"secret": {$ne: null}})
        .then(function(foundUsers){
            res.render("secrets", {usersWithSecrets:foundUsers});
        })
        .catch((err)=>{
            console.log(err);
        })
        /*
        if (req.isAuthenticated()){
            res.render("secrets")
        } else {
            res.redirect("/login")
        } 
        */
    })
 
//LOGOUT
app.route('/logout')
    .get((req,res)=>{
        req.logOut((err)=>{
            if(err){
                console.log(err)
            } else {
                res.redirect('/')
            }
        });
        
    })
app.post("/submit",function(req,res){
    const submittedsecret=req.body.secret;
    User.findById(req.user.id)
        .then(function(founudUser){
            founudUser.secret=submittedsecret;
            founudUser.save()
                .then(()=>{
                    res.redirect("/secrets");
                });
        })
        .catch((err)=>{
            console.log(err);
        })
})
app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    } else{
        res.redirect("/login");
    }

})
//listen to port 3000
app.listen(3000, ()=>{
    console.log('app listening on port 3000')
})