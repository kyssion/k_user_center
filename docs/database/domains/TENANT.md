# TENANT：业务线、租户、组织与成员

- 存储：`business_lines`、`tenants`、`tenant_domains`、`organizations`、`memberships`、`invitations`、`groups`、`group_members`。
- 聚合：`Tenant`、`Organization`、`Membership`、`Invitation`、`Group`。
- 代码规则：全局/租户/Membership 状态正交；组织树防环；邀请目标和权限上界；全链路租户隔离。
- 禁止：仅靠前端或查询后过滤实现隔离；跨租户父组织、组成员或角色授予。
- 事件：租户状态、组织变化、成员加入/离开、邀请消费、组成员变化。
- 门禁：`AT-TENANT-*`、跨租户搜索/缓存/事件/批量接口负向测试。

