# acw_sc__v2 分析范围

| 字段 | 内容 |
|------|------|
| auth | 用户在当前任务中明确指定目标接口并要求实现兼容功能 |
| in_scope | `https://anyrouter.top/api/user/sign_in` 的内联 `acw_sc__v2` 挑战，以及当前插件的请求链路 |
| network_profile | 仅对指定接口执行普通 GET/POST 验证请求，不做扫描、枚举或高频访问 |
| deliverable | 纯 Python 算法转译、按算法指纹缓存、Cookie 重试、站点级 Beta 开关和回归测试 |
| out_of_scope | 浏览器指纹挑战、验证码、非 `acw_sc__v2` 算法、账号或凭据获取 |
