// Package encryption 是 AES / SM4 / RSA / SM2 / ChaCha20-Poly1305 的统一加解密门面。
//
// 六个入口函数覆盖全部能力：
//
//	Encrypt      对称/非对称加解密      → standard.IEncrypt
//	EncryptSign  加解密 + 签名验签      → standard.IEncryptSign
//	Sign         签名验签               → standard.ISign
//	Generate     密钥生成               → standard.IGenerate
//	Padding      填充实现               → standard.IPadding
//	Stream       流式加解密             → standard.IStream
//
// 所有入口都接受同一组选项（Option）：WithType / WithModel / WithPadding /
// WithKey / WithIV / WithPubKey / WithPriKey / WithFormatType，以及按算法下钻的
// WithAESOptions / WithSM4Options / WithRSAOptions / WithSM2Options /
// WithChaCha20Poly1305Options / WithGRSAOptions / WithGSM2Options。
// 门面层选项是默认值，算法层选项优先级更高。
//
// 默认配置：
//
//	Encrypt      AES + CBC + PKCS#7 + Base64
//	EncryptSign  RSA + PKCS#1 v1.5 + Base64
//	Sign         RSA + PKCS#1 v1.5 + Base64
//	Generate     RSA 2048 + PEM
//
// 错误模型：与输入数据相关的失败（密钥格式、IV 长度、密文长度、填充、认证）
// 返回包装了 standard 包哨兵的 error，可用 errors.Is 判断；不支持的算法/模式
// 组合属于编程错误，会 panic。
//
// 并发：构造完成后的实例可安全并发使用；密钥/IV/UID 在构造时已被复制。
//
// 完整参考见仓库中的 USAGE.md；性能基线见 PERFORMANCE.md。
package encryption
