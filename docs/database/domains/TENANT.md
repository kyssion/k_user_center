# TENANT：业务线、租户、组织与成员

- 持久化范围：`business_lines`、`tenants`、`tenant_domains`、`organizations`、`memberships`、`invitations`、`groups`、`group_members`。
- 业务模型边界：`BusinessLine`、`Tenant`、`Organization`、`Membership`、`Invitation`、`Group`。
- 权威边界：TENANT 持有业务线、租户、组织、成员、邀请和组关系；PLT/OAP/AUTHZ 只引用其作用域与安全水位，不得建立重复业务线或租户状态。
- 业务模型要求：持久化模型必须支持全局/租户/Membership 状态正交、Membership 终态历史与重新加入新记录、组织树防环、邀请目标和权限上界以及全链路租户隔离所需事实。
- 禁止：仅靠前端或查询后过滤实现隔离；以 RLS/Policy、租户 Schema 或租户数据库账号作为唯一租户隔离来源；跨租户父组织、组成员或角色授予。
- 事件：租户状态、组织变化、成员加入/离开、邀请消费、组成员变化。
- 门禁：`AT-TENANT-*`、跨租户搜索/缓存/事件/批量接口负向测试；未配置可选 RLS/Policy 时代码侧隔离结果不变。
