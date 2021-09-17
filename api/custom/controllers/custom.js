const { sanitizeEntity } = require("strapi-utils");
const bcrypt = require("bcrypt");

module.exports = {
  changePassword: async (ctx) => {
    const { old_password, new_password, user_id } = ctx.request.body;

    try {
      const u = await strapi
        .query("user", "users-permissions")
        .find({ id: user_id });
      const prev_password = u[0].password;

      const is_old_password_valid = await bcrypt.compare(
        old_password,
        prev_password
      );

      const nw_pwd = await bcrypt.hash(new_password, 10)

      // update password
      if (is_old_password_valid) {
        await strapi
          .query("user", "users-permissions")
          .update({ id: user_id }, { password: nw_pwd });
        return { resp_code: "000", resp_desc: "Password updated successfully" };
      } else {
        return { resp_code: "123", resp_desc: "invalid password" };
      }
    } catch (err) {
      return err;
    }
  },
};
