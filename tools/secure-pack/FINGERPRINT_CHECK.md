# Fingerprint check (Out-of-band) / 指紋確認（別経路）

## 日本語
公開鍵の「指紋（fingerprint）」は、**ファイル送付とは別の経路**で確認してください。  
例：電話、対面、別Slack/別メールなど。

1) 相手から受け取った fingerprint を **別経路で読み上げ**して照合  
2) OKなら `gpg --import <pubkey.asc>`  
3) `gpg --fingerprint <KEYID/EMAIL>` で再確認  
4) `recipients/<client>.txt` に fingerprint を登録（公開情報）

## English
Verify key fingerprints **out-of-band** (separate channel).
Examples: phone call, in-person, different messaging/email channel.

1) Compare fingerprint over an independent channel  
2) Import: `gpg --import <pubkey.asc>`  
3) Confirm: `gpg --fingerprint <KEYID/EMAIL>`  
4) Add the fingerprint to `recipients/<client>.txt`
