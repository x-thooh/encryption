// Package standard 定义加密门面层与各适配器共享的接口、枚举常量与错误哨兵。
//
// 该包只放接口、常量和错误值，不依赖 adapter 或 pkg 下的任何实现，
// 以免形成反向依赖。调用方通常只需要其中的枚举常量（Type / Model /
// PaddingType / FormatType）和错误哨兵（ErrInvalidKey 等）。
package standard
