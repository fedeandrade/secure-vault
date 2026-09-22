-- A lápide de exclusão saiu: `DELETE` passou a apagar a linha, como no lado
-- Python. Ela escondia o registro do `GET` mas o mantinha no banco, decifrável
-- por qualquer chave futura do dono — porque o envelope faz a `vaultKey` nunca
-- rodar — e não havia purga em lugar nenhum do repositório.
ALTER TABLE "Credential" DROP COLUMN "deletedAt";
