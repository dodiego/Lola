module.exports = {
  roles: {
    users: {
      can: [
        {
          name: '*',
          operation: 'create',
          when: ctx => ctx.node._label !== 'users'
        },
        {
          name: '*',
          operation: 'update',
          when: ctx => ctx.user._id === ctx.node._id || ctx.node.user_id === ctx.user._id
        },
        {
          name: '*',
          operation: 'delete',
          when: ctx => ctx.user._id === ctx.node.user_id
        },
        {
          name: '*',
          operation: 'read',
          when: ctx => !ctx.node.deleted
        },
        {
          name: '*',
          operation: '*',
          when: ctx => ctx.user.is_admin
        }
      ]
    }
  }
}
