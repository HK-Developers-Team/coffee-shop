import React, { createContext, useState, useEffect } from "react";
import jwt_decode from "jwt-decode";
import API from "../API";

export const UserContext = createContext();

export const UserProvider = ({ children }) => {
  const [userDetail, setUserDetail] = useState({});
  const [isLogin, setIsLogin] = useState(false);

  useEffect(() => {
    const getUserDetail = () => {
      if (isLogin) {
        const token = localStorage.getItem("token");
        const decode = jwt_decode(token);
        const { username } = decode;
        API.get(`/api/user/${username}`)
          .then(res => console.log(res))
          .catch(err => console.log(err));
      }
    };
    getUserDetail();
  }, [isLogin]);

  return (
    <UserContext.Provider
      value={{ userDetail, setUserDetail, isLogin, setIsLogin }}
    >
      {children}
    </UserContext.Provider>
  );
};
