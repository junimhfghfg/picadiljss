# KeyAuth → Firebase Webhook Server

Servidor Node.js que recebe webhooks do KeyAuth e salva tudo no Firebase Realtime Database.

---

## Estrutura no Firebase

```
picaatuh-default-rtdb
├── logins/
│   └── <username>/
│       └── <autoId>: { username, key, ip, hwid, timestamp, ... }
├── registers/
│   └── <autoId>: { username, key, ip, hwid, email, timestamp, ... }
├── keys/
│   └── <autoId>: { key, appName, createdBy, timestamp, ... }
├── events/
│   └── <eventType>/
│       └── <autoId>: { ... }
└── users/
    └── <username>: { lastLogin, lastIp, lastHwid, registeredAt, ... }
```

---

## Passo 1 — Baixar o serviceAccount.json do Firebase

1. Acesse [https://console.firebase.google.com](https://console.firebase.google.com)
2. Selecione o projeto **picaatuh**
3. Clique em **Configurações do projeto** (ícone de engrenagem) → **Contas de serviço**
4. Clique em **Gerar nova chave privada**
5. Salve o arquivo baixado como **`serviceAccount.json`** dentro da pasta `keyauth-firebase-webhook/`

---

## Passo 2 — Instalar dependências

```bash
cd keyauth-firebase-webhook
npm install
```

---

## Passo 3 — Iniciar o servidor

```bash
npm start
```

O servidor vai rodar em `http://localhost:3000`.

> Para desenvolvimento com reload automático: `npm run dev`

---

## Passo 4 — Expor o servidor na internet (para o KeyAuth alcançar)

O KeyAuth precisa de uma URL pública para disparar os webhooks.
Use o **ngrok** para isso enquanto testa localmente:

```bash
# Instale o ngrok: https://ngrok.com/download
ngrok http 3000
```

Ele vai gerar uma URL pública tipo:
```
https://abc123.ngrok-free.app
```

Use essa URL como base nos webhooks do KeyAuth.

> Em produção, hospede o servidor em Railway, Render, VPS, etc.

---

## Passo 5 — Configurar os Webhooks no KeyAuth

1. Acesse o painel do KeyAuth: [https://keyauth.cc/app/](https://keyauth.cc/app/)
2. Selecione sua aplicação **Picadilha**
3. Vá em **Settings** → **Webhooks**
4. Adicione os webhooks abaixo:

| Evento           | URL                                         |
|------------------|---------------------------------------------|
| Login            | `https://SUA-URL/webhook/login`             |
| Register         | `https://SUA-URL/webhook/register`          |
| Key Created      | `https://SUA-URL/webhook/key-created`       |
| (ou use um só)   | `https://SUA-URL/webhook/all`               |

5. Salve e teste clicando em **Send Test**

---

## Endpoints disponíveis

| Método | Rota                   | Descrição                          |
|--------|------------------------|------------------------------------|
| POST   | `/webhook/login`       | Salva cada login no Firebase       |
| POST   | `/webhook/register`    | Salva novo registro + cria usuário |
| POST   | `/webhook/key-created` | Salva key criada                   |
| POST   | `/webhook/all`         | Endpoint genérico para tudo        |
| GET    | `/`                    | Healthcheck (verifica se está online) |

---

## Estrutura de arquivos

```
keyauth-firebase-webhook/
├── server.js          ← servidor principal
├── package.json
├── .env               ← variáveis de ambiente (não commitar)
├── .gitignore
├── serviceAccount.json  ← baixar do Firebase Console (não commitar)
└── README.md
```

---

## Regras do Firebase Realtime Database

Adicione estas regras no Firebase Console → **Realtime Database** → **Regras**
para que apenas o servidor (Admin SDK) possa escrever:

```json
{
  "rules": {
    ".read": false,
    ".write": false
  }
}
```

O Admin SDK ignora essas regras, então o servidor continua gravando normalmente.
Nenhum cliente externo consegue ler ou escrever diretamente.
