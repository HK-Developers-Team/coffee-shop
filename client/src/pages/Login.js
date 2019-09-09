import React, { useState, useContext } from "react";
import { Button, Form, FormGroup, Label, Input } from "reactstrap";
import API from "../API";
import { UserContext } from "../Contexts/UserContext";

const LoginPage = ({ history }) => {
  const { setIsLogin } = useContext(UserContext);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const onChangeUsername = e => {
    setUsername(e.target.value);
  };
  const onChangePassword = e => {
    setPassword(e.target.value);
  };

  const onLogin = e => {
    e.preventDefault();
    API.post("/api/user/login", { username, password })
      .then(res => {
        if (res.data.success) {
          document.cookie = `token=${res.data.token}`;
          localStorage.setItem("token", res.data.token);
          setIsLogin(true);
          history.push("/");
        } else {
          localStorage.removeItem("token");
          setIsLogin(false);
          history.push("/login");
        }
      })
      .catch(err => console.log(err));
  };
  return (
    <div>
      <Form onSubmit={onLogin}>
        <FormGroup>
          <Label for="username">Username</Label>
          <Input
            type="text"
            name="username"
            id="username"
            value={username}
            placeholder="Enter username"
            onChange={onChangeUsername}
          />
        </FormGroup>
        <FormGroup>
          <Label for="password">Password</Label>
          <Input
            type="password"
            name="password"
            id="password"
            value={password}
            placeholder="Enter password"
            onChange={onChangePassword}
          />
        </FormGroup>
        <Button>Submit</Button>
      </Form>
    </div>
  );
};

export default LoginPage;
