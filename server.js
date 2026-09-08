const path = require('path');
const express = require('express');
require('dotenv').config();

const app = express();
const port = Number(process.env.PORT || 3000);

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(port, () => console.log(`Pass vault running at http://localhost:${port}`));
