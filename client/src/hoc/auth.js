import React, { useEffect } from 'react'
import { useDispatch } from "react-redux"
import { useNavigate } from "react-router-dom"
import { auth } from '../_actions/user_action'

export default function (SpecificComponent, option, adminRoute = null) {
  /**
   * option
   * null: 아무나 출입이 가능한 페이지
   * true: 로그인한 유저만 출입이 가능한 페이지
   * false: 로그인한 유저는 출입 불가능한 페이지
   * 
   * adminRoute
   * true: admin 유저만 들어가기를 원하는 페이지
   */

  function AuthenticationCheck(props) {
    const dispatch = useDispatch()
    const navigate = useNavigate()

    useEffect(() => {
      dispatch(auth()).then(response => {
        console.log(response)
        //로그인 하지 않은 상태
        if (!response.payload.isAuth) {
          if (option) {
            navigate('/login')
          }
        }
        //로그인한 상태
        else {
          if (adminRoute && !response.payload.isAdmin) {
            navigate('/')
          } else {
            if (!option) {
              navigate('/')
            }
          }

        }
      })
    }, [])
    return (
      <SpecificComponent />
    )
  }

  return <AuthenticationCheck />
}