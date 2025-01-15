require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/',(req,res)=>{
    res.status(200).json({ msg:'Bem vindo a nossa API' })
})

//private route
app.get('/user/:id', checkToken, async(req,res) => {
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id,'-password')

    if(!user){
        return res.status(404).json({msg:"user not found"})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({msg:"acesso negado!"})
    }
    try{
        const secret = process.env.SECRET
        
        jwt.verify(token, secret)

        next()

    }catch(error){
        return res.status(400).json({msg:"token invalido"})
    }
}

app.post('/auth/register', async(req,res) => {
    const {name, email, password, confirmPassword} = req.body

    if(!name) {
        return res.status(422).json({msg:'O nome é obrigatorio'})
    }
    if(!email) {
        return res.status(422).json({msg:'O email é obrigatorio'})
    }
    if(!password) {
        return res.status(422).json({msg:'O password é obrigatorio'})
    }
    if (password !== confirmPassword) {
        return res.status(422).json({msg:'Senhas não conferem'})
    }

    const userExists = await User.findOne({ email: email })
    if(userExists){
        return res.status(422).json({msg: 'Já existe um usuário cadastrado com este e-mail'})
    }

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()
        res.status(201).json({msg: 'User created with success'})
    } catch(error) {
        res.status(500).json({msg: 'Internal Error'})
    }
    
})

app.post('/auth/login', async (req, res)=>{
    const {email, password} = req.body
    
    if(!email) {
        return res.status(422).json({msg:'O email é obrigatorio'})
    }
    if(!password) {
        return res.status(422).json({msg:'O password é obrigatorio'})
    }
    
    //check if user exists
    const userExists = await User.findOne({ email: email })
    if(!userExists){
        return res.status(404).json({msg: 'User not found'})
    }
    
    //check if password match
    const checkPassword = await bcrypt.compare(password, userExists.password)
    if(!checkPassword){
        return res.status(404).json({msg: 'Invalid password'})
    }
    
    try {
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
            id: userExists._id,
            },
            secret,
        )
        res.status(200).json({msg: "Autenticacao com sucesso", token})
    } catch(err) {
        console.log(err)
        res.status(500).json({msg: 'Internal Error',err})
    }
})

mongoose
    .connect(`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.gisay.mongodb.net/usersApp?retryWrites=true&w=majority&appName=Cluster0`)
    .then(()=>{
    app.listen(3000)
    console.log('connected')
})
    .catch((err)=>console.log(err))


