import React from "react";
import "./assets/style/main.scss";
import { Container } from "reactstrap";
import { Switch, Route } from "react-router-dom";

import AppNavBar from "./Components/AppNavBar";
import LoginPage from "./pages/Login";
import { UserProvider } from "./Contexts/UserContext";
import HomePage from "./pages/Home";

const App = () => {
  return (
    <UserProvider>
      <div>
        <Route component={AppNavBar} />
        <Container>
          <Switch>
            <Route path="/" exact component={HomePage} />
            <Route path="/login" component={LoginPage} />
          </Switch>
        </Container>
      </div>
    </UserProvider>
  );
};

export default App;
