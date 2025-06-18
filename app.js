const cookieParser = require('cookie-parser');
const express = require('express');
const app = express();
const Path = require('path');
const userModel = require('./models/user');
const postModel = require('./models/post');

const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
const user = require('./models/user');
const { log } = require('console');

app.set('view engine', 'ejs');
app.use(cookieParser())
app.use(express.static(Path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', function (req, res) {
    res.render('index');
});

app.get('/login', function (req, res) {
    res.render('login');
});

app.get('/profile', isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({ email: req.user.email }).populate('posts');
    res.render('profile', { user });
});

app.get('/like/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({ _id: req.params.id }).populate('user');
    if (post.likes.indexOf(req.user.userId) === -1) {
        post.likes.push(req.user.userId);
    } else {
        post.likes.splice(post.likes.indexOf(req.user.userId), 1);
    }
    await post.save();
    res.redirect('/profile');
});

app.get('/edit/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({ _id: req.params.id }).populate('user');
    res.render('edit', { post });
});

app.post('/update/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOneAndUpdate({ _id: req.params.id }, { content: req.body.content });
    res.redirect('/profile');
});

app.post('/post', isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({ email: req.user.email });
    let { content } = req.body;
    let post = await postModel.create({
        user: user._id,
        content
    });
    user.posts.push(post._id);
    await user.save();
    res.redirect('/profile');
});

app.post('/register', async function (req, res) {
    const { username, name, email, password, age } = req.body;
    let user = await userModel.findOne({ email });
    if (user) return res.status(500).send('something already exist')

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, async (err, hash) => {
            let user = await userModel.create({
                username,
                email,
                name,
                age,
                password: hash
            })
            let token = jwt.sign({ email: email, userId: user._id }, 'secret')
            res.cookie('token', token)
            res.redirect('/login');
        })
    })
});

app.post('/login', async function (req, res) {
    const { email, password } = req.body;

    let user = await userModel.findOne({ email });
    if (!user) return res.status(500).send('user not found')

    bcrypt.compare(password, user.password, function (err, result) {
        if (result) {
            let token = jwt.sign({ email: email, userId: user._id }, 'secret')
            res.cookie('token', token)
            res.status(200).redirect('/profile')
        }
        else res.redirect('/login');
    });
});

app.get('/logout', function (req, res) {
    res.clearCookie('token');
    res.redirect('/login');
});

function isLoggedIn(req, res, next) {
    if (req.cookies.token === "") return res.redirect('/login');
    else {
        let data = jwt.verify(req.cookies.token, 'secret',)
        req.user = data;
        next();
    }
}

app.listen(3000, function () {
    console.log('listening on port 3000!');
});