const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const client = new PrismaClient();

class AuthController {
    static async cadastrar(req, res) {
        const { nome, email, password } = req.body;

        const salt = bcryptjs.genSaltSync(8);
        const hashSenha = bcryptjs.hashSync(password, salt);

        try {
            const usuario = await client.usuario.create({
                data: {
                    nome,
                    email,
                    password: hashSenha,
                },
            });

            const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

            res.json({
                mensagem: "Usuário cadastrado com sucesso",
                erro: false,
                token: token
            });
        } catch (e) {
            res.json({
                mensagem: "Erro ao cadastrar usuário",
                erro: true
            });
        }
    }

    static async login(req, res) {
        const { email, password } = req.body;

        try {
            const usuario = await client.usuario.findUnique({
                where: { email: email },
            });

            if (!usuario) {
                return res.json({
                    mensagem: "Usuário não encontrado",
                    erro: true
                });
            }

            const senhaCorreta = bcryptjs.compareSync(password, usuario.password);
            if (!senhaCorreta) {
                return res.json({
                    mensagem: "Senha incorreta",
                    erro: true
                });
            }

            const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

            res.json({
                mensagem: "Login realizado com sucesso",
                erro: false,
                token: token
            });
        } catch (e) {
            res.json({
                mensagem: "Erro ao realizar login",
                erro: true
            });
        }
    }
}

module.exports = AuthController;
