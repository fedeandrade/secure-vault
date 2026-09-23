-- `lockedUntil` saiu. Ela era escrita pelo login (sempre `null`, no reset) e
-- lida por ninguém — o atraso exponencial sempre viveu em `failedAttempts`.
--
-- Coluna órfã com esse nome não é neutra: convida o próximo a "só ligar o
-- lockout". E num registro singleton — o vault tem um dono só — lockout duro é
-- auto-DoS: qualquer estranho mandando 1 requisição errada por segundo mantém o
-- portão fechado para o DONO, indefinidamente, de graça.
ALTER TABLE "VaultConfig" DROP COLUMN "lockedUntil";
