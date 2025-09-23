const path = require("path")
const bcryptjs = require("bcryptjs")
const jwt = require("jsonwebtoken")

const { PrismaClient } = require("@prisma/client");
const client = new PrismaClient()


class authController{
     static async cadastrar(req,res) {
        const {nome, email, senha, tipo} = req.body

        const salt = bcryptjs.genSaltSync(8)
        const hashSenha = bcryptjs.hashSync(senha, salt)
        
       const usuario = await client.usuario.create({
        data:{
          nome, 
          email,
          senha: hashSenha,
          tipo
        },})

        res.json({
            usuarioId: usuario.id,
        });
    }
    static async login(req, res){
      const {email, senha} = req.body;
      //verificar se o usuario existe
      const usuario = await client.usuario.findUnique({
        where: {
          email: email,
        },
      })
      if(!usuario){
        return res.json({
          msg: "Usuário não encontrado!",
      })
    } 
    //verificar se a senha esta correta
    const senhaCorreta = bcryptjs.compareSync(senha, usuario.senha)
    if(!senhaCorreta){
      return res.josn({msg: "Senha Incorreta!"}) 
    }
    //emitir um token
    const token = jwt.sign({id: usuario.id}, process.env.SENHA_SERVIDOR, {expiresIn: "2h"})
    res.json({
      msg: "Autenticado!",
      token: token,
    });
  }

  static async verificaAutenticacao(req, res, next){
    const authHeader = req.headers["authorization"]
    if(authHeader){

      const token = authHeader.split(" ")[1]

      jwt.verify(token, process.env.SENHA_SERVIDOR, (err, payload) =>{
        if (err){
          return res.json({
            msg:"token invalido!",
          })
        }

        req.usuarioId = payload.id
        next()
      })

    }else{
     return res.json({
      msg: "token não encontrado",
    })
  }
  }

  static async verificaIsAdmin(req, res, next){
    if(!req.usuarioId){
      return res.json({
        msg: "você não está autenticado"
      })
    }

    const usuario = await client.usuario.findUnique({
      where: {
        id: req.usuarioId
      }
    })

    if(!usuario.IsAdmin){
      return res.json({
        msg: "Acesso negado, você não é um administrador"
      })
    }

    next()

  }
}


module.exports = authController;