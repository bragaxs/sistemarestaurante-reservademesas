const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const client = new PrismaClient();

class AuthController {
  static async cadastrar(req, res) {
    const { nome, email, password } = req.body;

    if (!nome || !email || !password) {
      return res.status(400).json({
        mensagem: "Nome, email e senha são obrigatórios",
        erro: true
      });
    }

    const salt = bcryptjs.genSaltSync(8);
    const hashPassword = bcryptjs.hashSync(password, salt);

    try {
      const usuario = await client.usuario.create({
        data: {
          nome,
          email,
          password: hashPassword,
        },
      });

      const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

      res.status(201).json({
        mensagem: "Usuário cadastrado com sucesso",
        erro: false,
        token
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({
        mensagem: "Erro ao cadastrar usuário, tente novamente trocando o nome ou email",
        erro: true
      });
    }
  }

  static async login(req, res) {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        mensagem: "Email e senha são obrigatórios",
        erro: true
      });
    }

    try {
      const usuario = await client.usuario.findUnique({
        where: { email },
      });

      if (!usuario) {
        return res.status(404).json({
          mensagem: "Usuário não encontrado",
          erro: true
        });
      }

      const passwordCorrect = bcryptjs.compareSync(password, usuario.password);
      if (!passwordCorrect) {
        return res.status(401).json({
          mensagem: "Senha incorreta",
          erro: true
        });
      }

      const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

      res.json({
        mensagem: "Login realizado com sucesso",
        erro: false,
        token
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({
        mensagem: "Erro ao realizar login",
        erro: true
      });
    }
  }
}

module.exports = AuthController;
