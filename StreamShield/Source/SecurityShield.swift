//
//  SecurityShield.swift
//  StreamShield
//
//  Created by Qindi on 31/10/24.
//

import Foundation
import UIKit
import nuSDKService
import AVFoundation
import AVKit
import CoreTelephony
import CryptoKit
import MachO
import CommonCrypto
import SystemConfiguration.CaptiveNetwork
import CoreLocation
import Network
import CoreMotion

public class SecurityShield: NSObject {
    
    static var dispatch: DispatchGroup?
    
    public static func check(appName: String, apiKey: String) {
        Preference.setAppId(value: appName)
        Preference.setAccount(value: apiKey)
        DispatchQueue.global().async {
            do {
                var id = Preference.getConnectionID()
                if id.isEmpty {
                    let sDID = UIDevice.current.identifierForVendor?.uuidString ?? "UNK-DEVICE"
                    id = String(sDID[sDID.index(sDID.endIndex, offsetBy: -5)...])
                    Preference.setConnectionID(value: id)
                }
                if !API.bnuSDKServiceReady() || API.nGetCLXConnState() == 0 {
                    let address = getAddressNew(apiKey:Preference.getAccount())
                    if address.isEmpty {
                        return
                    }
                    let addressConn = address.components(separatedBy: ":")[0]
                    let port = Int(address.components(separatedBy: ":")[1]) ?? 0
                    try API.initConnection(sAPIK: apiKey, cbiI: CallBackSS(), sTCPAddr: addressConn, nTCPPort: port, sUserID: id, sStartWH: "09:00")
                    while (!API.bnuSDKServiceReady() || API.nGetCLXConnState() == 0) {
                        Thread.sleep(forTimeInterval: 1)
                    }
                }
                pull()
            } catch {
                
            }
        }
    }
    
    private static func getAddressNew(apiKey: String) -> String {
        var result = ""
        let url = URL(string: "\(Preference.getDomainOpr())dipp/NuN1v3rs3/Qm3r4i0/get_ip_domain?account=\(apiKey)")!
        let urlConfig = URLSessionConfiguration.default
        let sessionDelegate = SelfSignedURLSessionDelegate()
        urlConfig.requestCachePolicy = .returnCacheDataElseLoad
        urlConfig.timeoutIntervalForRequest = 10.0
        urlConfig.timeoutIntervalForResource = 10.0
        let semaphore = DispatchSemaphore(value: 0)
        let task = URLSession(configuration: urlConfig, delegate: sessionDelegate, delegateQueue: nil).dataTask(with: url) {(data, response, error) in
            guard let data = data,
                let url = response?.url,
                let httpResponse = response as? HTTPURLResponse,
                let fields = httpResponse.allHeaderFields as? [String: String] else {
                semaphore.signal()
                return
            }
            let dataEncode = String(data: data, encoding: .utf8)!
            if !dataEncode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                let dataDecodeBase64 = String(data: Data(base64Encoded: dataEncode)!, encoding: .utf8)!
                let dataRealDecode = UtilsSS.decrypt(str: dataDecodeBase64)
                do {
                    if let jsonData = dataRealDecode.data(using: .utf8), let jsonObject = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] {
                        var newDomain = jsonObject["domain"] as! String
                        let jsonAddress = jsonObject["address"] as! [[String: Any]]
                        let newIp = jsonAddress[0]["ip"] as! String
                        let newPort = jsonAddress[0]["portI"] as! String
                        if newDomain.substring(from: newDomain.count-1, to: nil) != "/" {
                            newDomain += "/"
                        }
                        if (newIp+":"+newPort) != Preference.getIpOpr() || newDomain != Preference.getDomainOpr() {
                            //check new domain
                            if checkNewDomain(newDomain) {
                                Preference.setDomainOpr(value: newDomain)
                                Preference.setIpPortOpr(value: (newIp+":"+newPort))
                            }
                        }
                    }
                } catch {
                    
                }
            }
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .distantFuture)
        result = Preference.getIpOpr()
        return result
    }
    
    private static func checkNewDomain(_ newDomain: String) -> Bool {
        var result = false
        let url = URL(string: "\(newDomain)dipp/NuN1v3rs3/Qm3r4i0/get_ip_domain?account=\(Preference.getAccount())")!
        let urlConfig = URLSessionConfiguration.default
        let sessionDelegate = SelfSignedURLSessionDelegate()
        urlConfig.requestCachePolicy = .returnCacheDataElseLoad
        urlConfig.timeoutIntervalForRequest = 10.0
        urlConfig.timeoutIntervalForResource = 10.0
        let semaphore = DispatchSemaphore(value: 0)
        let task = URLSession(configuration: urlConfig, delegate: sessionDelegate, delegateQueue: nil).dataTask(with: url) {(data, response, error) in
            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.statusCode == 200 {
                    guard let url = response?.url,
                        let fields = httpResponse.allHeaderFields as? [String: String] else {
                        semaphore.signal()
                        return
                    }
                    result = true
                }
            }
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .distantFuture)
        return result
    }
    
    private static func pull() {
        let me: String! = SecureUserDefaultsSS.shared.value(forKey: "me") ?? Preference.getConnectionID()
        let tmessage = TMessageSS()
        tmessage.mCode = "SS01"
        tmessage.mStatus = CoreMessage_TMessageUtil.getTID()
        tmessage.mPIN = me
        tmessage.mBodies["Api"] = Preference.getAccount()
        tmessage.mBodies["AAN"] = Preference.getAppId()
        tmessage.mBodies["type"] = "0"
        DispatchQueue.global().async{
            postDataWithCookiesAndUserAgent(from: URL(string: Preference.getDomainOpr() + "get_feature_access_new")!) { data, response, error in
                let response = response as? HTTPURLResponse
                if response?.statusCode != 200 || error != nil {
                    return
                }
                if let data = data, let responseString = String(data: data, encoding: .utf8) {
                    Process.check(dataSS: responseString)
                } else {
                    Process.check(dataSS: "")
                }
            }
//            if let response = Service.writeSync(message: tmessage) {
//                if response.isOk() {
//                    let dataResp = response.getBody(key: "A112")
//                    Process.check(dataSS: dataResp)
//                } else {
//                    Process.check(dataSS: "")
//                }
//            } else {
//                Process.check(dataSS: "")
//            }
        }
    }
    
    static func postDataWithCookiesAndUserAgent(from url: URL, parameter: [String: Any] = [:], parameters: [[String: Any]] = [], isFormData: Bool = false, completion: @escaping (Data?, URLResponse?, Error?) -> ()) {
        let apiKey: String = Preference.getAccount()
        let me: String? = SecureUserDefaultsSS.shared.value(forKey: "me")
        var defaultParameter: [String : Any] = [
            "app_id": Preference.getAppId(),
            "apikey": apiKey,
        ]
        if me != nil {
            defaultParameter["f_pin"] = me
        }
        var jsonArray: [[String: Any]] = []
        if parameters.count == 0 {
            jsonArray.append(defaultParameter)
        } else {
            jsonArray = parameters
        }
        var jsonData: Data!
        if !isFormData {
            jsonData = try? JSONSerialization.data(withJSONObject: parameter.count == 0 ? jsonArray : parameter, options: [])
        } else {
            let formData = parameter.map { "\($0.key)=\($0.value)" }.joined(separator: "&")
            jsonData = formData.data(using: .utf8)
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
//        request.setValue(Utils.getUserAgent(), forHTTPHeaderField: "User-Agent")
//        request.setValue(Utils.getCookiesMobile(), forHTTPHeaderField: "Cookie")
        if isFormData {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        } else {
            request.setValue("application/json;charset=UTF-8", forHTTPHeaderField: "Content-Type")
            request.setValue("application/json", forHTTPHeaderField: "Accept")
        }
        request.httpBody = jsonData
        let urlConfig = URLSessionConfiguration.default
        urlConfig.timeoutIntervalForRequest = 30.0
        urlConfig.timeoutIntervalForResource = 60.0
        let sessionDelegate = SelfSignedURLSessionDelegate()
        let session = URLSession(configuration: urlConfig, delegate: sessionDelegate, delegateQueue: nil)
        let task = session.dataTask(with: request, completionHandler: completion)
        task.resume()
    }
    
    private static func showToast(message : String, font: UIFont = UIFont.systemFont(ofSize: 12, weight: .medium), controller: UIViewController) {
        
        let toastContainer = UIView(frame: CGRect())
        toastContainer.backgroundColor = controller.traitCollection.userInterfaceStyle == .dark ? .white.withAlphaComponent(0.6) : UIColor.mainColorSS.withAlphaComponent(0.6)
        toastContainer.alpha = 0.0
        toastContainer.layer.cornerRadius = 25;
        toastContainer.clipsToBounds  =  true
        
        let toastLabel = UILabel(frame: CGRect())
        toastLabel.textColor = controller.traitCollection.userInterfaceStyle == .dark ? .blackDarkModeSS : UIColor.white
        toastLabel.textAlignment = .center;
        toastLabel.font = font
        toastLabel.text = message
        toastLabel.clipsToBounds  =  true
        toastLabel.numberOfLines = 0
        
        toastContainer.addSubview(toastLabel)
        controller.view.addSubview(toastContainer)
        controller.view.bringSubviewToFront(toastContainer)
        
        toastLabel.translatesAutoresizingMaskIntoConstraints = false
        toastContainer.translatesAutoresizingMaskIntoConstraints = false
        
        let a1 = NSLayoutConstraint(item: toastLabel, attribute: .leading, relatedBy: .equal, toItem: toastContainer, attribute: .leading, multiplier: 1, constant: 15)
        let a2 = NSLayoutConstraint(item: toastLabel, attribute: .trailing, relatedBy: .equal, toItem: toastContainer, attribute: .trailing, multiplier: 1, constant: -15)
        let a3 = NSLayoutConstraint(item: toastLabel, attribute: .bottom, relatedBy: .equal, toItem: toastContainer, attribute: .bottom, multiplier: 1, constant: -15)
        let a4 = NSLayoutConstraint(item: toastLabel, attribute: .top, relatedBy: .equal, toItem: toastContainer, attribute: .top, multiplier: 1, constant: 15)
        toastContainer.addConstraints([a1, a2, a3, a4])
        
        let c1 = NSLayoutConstraint(item: toastContainer, attribute: .leading, relatedBy: .equal, toItem: controller.view, attribute: .leading, multiplier: 1, constant: 65)
        let c2 = NSLayoutConstraint(item: toastContainer, attribute: .trailing, relatedBy: .equal, toItem: controller.view, attribute: .trailing, multiplier: 1, constant: -65)
        let c3 = NSLayoutConstraint(item: toastContainer, attribute: .bottom, relatedBy: .equal, toItem: controller.view, attribute: .bottom, multiplier: 1, constant: -75)
        controller.view.addConstraints([c1, c2, c3])
        
        UIView.animate(withDuration: 0.5, delay: 0.0, options: .curveEaseIn, animations: {
            toastContainer.alpha = 1.0
        }, completion: { _ in
            UIView.animate(withDuration: 0.5, delay: 1.5, options: .curveEaseOut, animations: {
                toastContainer.alpha = 0.0
            }, completion: {_ in
                toastContainer.removeFromSuperview()
            })
        })
    }
}

private class Process: NSObject, CLLocationManagerDelegate {
    static func check(dataSS : String) {
        if !dataSS.isEmpty {
            if let jsonArray = try? JSONSerialization.jsonObject(with: dataSS.data(using: String.Encoding.utf8)!, options: JSONSerialization.ReadingOptions()) as? [AnyObject] {
                do {
                    for jsonData in jsonArray {
                        if jsonData["check_keylogger"]! != nil {
                            Preference.setPreventKeylogger(value: jsonData["check_keylogger"]! as! String == "1")
                            Preference.setPreventKeyloggerAction(value: jsonData["action"]! as! String)
                            Preference.setKeyloggerAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setKeyloggerAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_screen_capture"]! != nil {
                            Preference.setPreventScreenCapture(value: jsonData["check_screen_capture"]! as! String == "1")
                            Preference.setPreventScreenCaptureAction(value: jsonData["action"]! as! String)
                            Preference.setCheckScreenCaptureAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setScreenCaptureAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_emulator"]! != nil {
                            Preference.setCheckEmulator(value: jsonData["check_emulator"]! as! String == "1")
                            Preference.setCheckEmulatorAction(value: jsonData["action"]! as! String)
                            Preference.setCheckEmulatorAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckEmulatorAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_rooted_device"]! != nil {
                            Preference.setCheckRooted(value: jsonData["check_rooted_device"]! as! String == "1")
                            Preference.setCheckRootedAction(value: jsonData["action"]! as! String)
                            Preference.setCheckRootedAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckRootedAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_outdated_os"]! != nil {
                            Preference.setCheckOutdatedOs(value: jsonData["check_outdated_os"]! as! String == "1")
                            Preference.setCheckOutdatedOsAction(value: jsonData["action"]! as! String)
                            Preference.setCheckOutdatedOsAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckOutdatedOsAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["minimum_ios_version"]! != nil {
                            Preference.setMinimumOsVersion(value: jsonData["minimum_ios_version"]! as! String)
                        }
                        if jsonData["check_sum"]! != nil {
                            Preference.setCheckTempering(value: jsonData["check_sum"]! as! String == "1")
                            Preference.setCheckTemperingAction(value: jsonData["action"]! as! String)
                            Preference.setCheckTemperingAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckTemperingAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_hook"]! != nil {
                            Preference.setCheckHooked(value: jsonData["check_hook"]! as! String == "1")
                            Preference.setCheckHookedAction(value: jsonData["action"]! as! String)
                            Preference.setCheckHookedAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckHookedAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_usb_debugging"]! != nil {
                            Preference.setCheckDebugging(value: jsonData["check_usb_debugging"]! as! String == "1")
                            Preference.setCheckDebuggingAction(value: jsonData["action"]! as! String)
                            Preference.setCheckDebuggingAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckDebuggingAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_screen_casting"]! != nil {
                            Preference.setCheckScreenCasting(value: jsonData["check_screen_casting"]! as! String == "1")
                            Preference.setCheckScreenCastingAction(value: jsonData["action"]! as! String)
                            Preference.setCheckScreenCastingAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckScreenCastingAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_screen_overlay"]! != nil {
                            Preference.setCheckScreenOverlay(value: jsonData["check_screen_overlay"]! as! String == "1")
                            Preference.setCheckScreenOverlayAction(value: jsonData["action"]! as! String)
                            Preference.setCheckScreenOverlayAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckScreenOverlayAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_call_forwarding"]! != nil {
                            Preference.setCheckCallForward(value: jsonData["check_call_forwarding"]! as! String == "1")
                            Preference.setCheckCallForwardAction(value: jsonData["action"]! as! String)
                            Preference.setCheckCallForwardAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckCallForwardAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["multiple_login"]! != nil {
                            Preference.setCheckMultipleLogin(value: jsonData["multiple_login"]! as! String == "1")
                            Preference.setCheckMultipleLoginAction(value: jsonData["action"]! as! String)
                            Preference.setCheckMultipleLoginAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckMultipleLoginAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_sim_swap"]! != nil {
                            Preference.setCheckSimSwap(value: jsonData["check_sim_swap"]! as! String == "1")
                            Preference.setCheckSimSwapAction(value: jsonData["action"]! as! String)
                            Preference.setCheckSimSwapAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckSimSwapAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["check_geovelocity"]! != nil {
                            Preference.setCheckGeoVelocity(value: jsonData["check_geovelocity"]! as! String == "1")
                            Preference.setCheckGeoVelocityAction(value: jsonData["action"]! as! String)
                            Preference.setCheckGeoVelocityAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckGeoVelocityAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        if jsonData["behavioral_analysis"]! != nil {
                            Preference.setCheckBehaviourAnalysis(value: jsonData["behavioral_analysis"]! as! String == "1")
                            Preference.setCheckBehaviourAnalysisAction(value: jsonData["action"]! as! String)
                            Preference.setCheckBehaviourAnalysisAlertTitle(value: jsonData["alert_title"]! as! String)
                            Preference.setCheckBehaviourAnalysisAlertMessage(value: jsonData["alert_message"]! as! String)
                        }
                        
                    }
                    if Preference.getPreventKeylogger() || Preference.getPreventScreenCapture() {
                        NotificationCenter.default.addObserver(self, selector: #selector(preventScreenRecording), name: UIScreen.capturedDidChangeNotification, object: nil)
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: {
                            if let window = UIApplication.shared.windows.first {
                                makeSecure(window: window)
                            }
                        })
                    } else {
                        if screen != nil {
                            screen?.removeFromSuperview()
                        }
                    }
                    subCheck(1)
                } catch {
                    
                }
            }
        } else {
            subCheck(1)
        }
    }
    
    private static var screen: UIView!
    @objc static func preventScreenRecording() {
        let isCaptured = UIScreen.main.isCaptured
        if isCaptured {
            blurScreen()
        }
        else {
            removeBlurScreen()
        }
    }

    private static func blurScreen(style: UIBlurEffect.Style = UIBlurEffect.Style.regular) {
        screen = UIScreen.main.snapshotView(afterScreenUpdates: false)
        let blurEffect = UIBlurEffect(style: style)
        let blurBackground = UIVisualEffectView(effect: blurEffect)
        screen.addSubview(blurBackground)
        blurBackground.frame = (screen.frame)
        if let window = UIApplication.shared.windows.first {
            window.addSubview(screen)
        } else {
        }
    }

    private static func removeBlurScreen() {
        screen?.removeFromSuperview()
    }
    
    private static func makeSecure(window: UIWindow) {
        let field = UITextField()

        let view = UIView(frame: CGRect(x: 0, y: 0, width: field.frame.self.width, height: field.frame.self.height))

        let image = UIImageView(image: UIImage.imageWithColorSS(color: .black, size: CGSize(width: UIScreen.main.bounds.width, height: UIScreen.main.bounds.height)))
        image.frame = CGRect(x: 0, y: 0, width: UIScreen.main.bounds.width, height: UIScreen.main.bounds.height)

        field.isSecureTextEntry = true

        window.addSubview(field)
        view.addSubview(image)

        window.layer.superlayer?.addSublayer(field.layer)
        field.layer.sublayers?.last!.addSublayer(window.layer)

        field.leftView = view
        field.leftViewMode = .always
    }
    
    /*
     * 1: Login from new device / multiple login detected
     * 2: Call redirection
     * 3: Sim change/swap
     * 4: Rooted device
     * 5: Emulator detected
     * 6: Developer mode/debugger (USB/WiFi) detected
     * 7: Screen recording/sharing/capture; keylogger
     * 8: Malware & suspicious apps
     * 9: App cloning
     * 10: Remote wipe
     * 11: Secure Folder
     * 12: Outdated OS
     * 13: Application Backup Detected
     * 14: Checksum / Tempering
     * 15: Screen Overlay
     * 16: Sideload app
     * 17: Behavioral Anomaly Detected
     * 18: Magisk Detected
     * 19: Rooted device by RootBeer
     * 20: Google Play Integrity
     * 21: Geovelocity
     * 22: Hook/Anti Frida Detected
     */
    
    static func subCheck(_ typeSecurity : Int) {
        if typeSecurity == 1 {
            if checkEmulator() {
//                print("ERROR 1")
                sendShieldErrorLog(code: 5)
                return
            }
            subCheck(2)
        } else if typeSecurity == 2 {
            if checkRootedDevice() {
//                print("ERROR 2")
                sendShieldErrorLog(code: 4)
                return
            }
            subCheck(3)
        } else if typeSecurity == 3 {
            if checkOutdatedOS() {
//                print("ERROR 3")
                sendShieldErrorLog(code: 12)
                return
            }
            subCheck(4)
        } else if typeSecurity == 4 {
            if checkTempering() {
//                print("ERROR 4")
                sendShieldErrorLog(code: 14)
                return
            }
            subCheck(5)
        } else if typeSecurity == 5 {
            if checkHooked() {
//                print("ERROR 5")
                sendShieldErrorLog(code: 22)
                return
            }
            subCheck(6)
        } else if typeSecurity == 6 {
            if checkDebugging() {
//                print("ERROR 6")
                sendShieldErrorLog(code: 6)
                return
            }
            subCheck(7)
        } else if typeSecurity == 7 {
            NotificationCenter.default.addObserver(self, selector: #selector(screenDidConnect), name: UIScreen.didConnectNotification, object: nil)
            NotificationCenter.default.addObserver(self, selector: #selector(screenDidDisconnect), name: UIScreen.didDisconnectNotification, object: nil)
            if checkScreenCasting() {
//                print("ERROR 7")
                sendShieldErrorLog(code: 7)
                return
            }
            subCheck(8)
        } else if typeSecurity == 8 {
            if checkScreenOverlay() {
//                print("ERROR 8")
                sendShieldErrorLog(code: 15)
                return
            }
            subCheck(9)
        } else if typeSecurity == 9 {
            if checkCallForward() {
//                print("ERROR 9")
                sendShieldErrorLog(code: 2)
                return
            }
            subCheck(10)
        } else if typeSecurity == 10 {
            if checkMultipleLogin() {
//                print("ERROR 10")
                sendShieldErrorLog(code: 1)
                return
            }
            subCheck(11)
        } else if typeSecurity == 11 {
            if checkSimSwap() {
//                print("ERROR 11")
                sendShieldErrorLog(code: 3)
                return
            }
            subCheck(12)
        } else if typeSecurity == 12 {
            if checkGeovelocity() {
//                print("ERROR 12")
                sendShieldErrorLog(code: 21)
                return
            }
            subCheck(13)
        } else if typeSecurity == 13 {
            if checkBehaviourAnalysis() {
//                print("ERROR 13")
                sendShieldErrorLog(code: 17)
                return
            }
        }
    }
    
    static func checkEmulator() -> Bool {
        if Preference.getCheckEmulator() && isEmulator() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckEmulatorAlertTitle(), message: Preference.getCheckEmulatorAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckEmulatorAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(2)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-101)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkRootedDevice() -> Bool {
        if Preference.getCheckRooted() && isRooted() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckRootedAlertTitle(), message: Preference.getCheckRootedAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckRootedAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(3)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkOutdatedOS() -> Bool {
        if Preference.getCheckOutdatedOs() {
            let requiredVersion = Preference.getMinimumOsVersion()
            let systemVersion = UIDevice.current.systemVersion
            let versionComponents = systemVersion.split(separator: ".").prefix(2)
            let versionString = versionComponents.joined(separator: ".")
            if let currentVersion = Double(versionString),
               let requiredVersionDouble = Double(requiredVersion) {
                if currentVersion < requiredVersionDouble {
                    DispatchQueue.main.async(execute: {
                        let alert = SSLibAlertController(title: Preference.getCheckRootedAlertTitle(), message: Preference.getCheckRootedAlertMessage(), preferredStyle: .alert)
                        if Preference.getCheckOutdatedOsAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                            alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                                subCheck(4)
                            }))
                            if UIApplication.shared.visibleViewController?.navigationController != nil {
                                UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                            } else {
                                UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                            }
                        } else {
                            alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                                exit(-103)
                            }))
                            if UIApplication.shared.visibleViewController?.navigationController != nil {
                                UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                            } else {
                                UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                            }
                        }
                    })
                    return true
                }
            } else {
            }
        }
        return false
    }
    
    static func checkTempering() -> Bool {
        if Preference.getCheckTempering() && isTempering() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckTemperingAlertTitle(), message: Preference.getCheckTemperingAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckTemperingAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(5)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkHooked() -> Bool {
        if Preference.getCheckHooked() && isHooked() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckHookedAlertTitle(), message: Preference.getCheckHookedAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckHookedAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(6)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkDebugging() -> Bool {
        if Preference.getCheckDebugging() && isDebugging() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckDebuggingAlertTitle(), message: Preference.getCheckDebuggingAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckDebuggingAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(7)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkScreenCasting() -> Bool {
        if Preference.getCheckScreenCasting() && isScreenCasting() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckScreenCastingAlertTitle(), message: Preference.getCheckScreenCastingAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckScreenCastingAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(8)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkScreenOverlay() -> Bool {
        if Preference.getCheckScreenOverlay() && isScreenOverlay() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckScreenOverlayAlertTitle(), message: Preference.getCheckScreenOverlayAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckScreenOverlayAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(9)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkCallForward() -> Bool {
        if Preference.getCheckCallForward() && isCallForwarded() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckCallForwardAlertTitle(), message: Preference.getCheckCallForwardAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckCallForwardAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(10)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkMultipleLogin() -> Bool {
        if Preference.getCheckMultipleLogin() && isMultipleLogin() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckMultipleLoginAlertTitle(), message: Preference.getCheckMultipleLoginAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckMultipleLoginAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(11)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkSimSwap() -> Bool {
        if Preference.getCheckSimSwap() && isSimSwap() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckSimSwapAlertTitle(), message: Preference.getCheckSimSwapAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckSimSwapAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(12)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkGeovelocity() -> Bool {
        if Preference.getCheckGeoVelocity() && isGeovelocityDetected() {
            DispatchQueue.main.async(execute: {
                let alert = SSLibAlertController(title: Preference.getCheckGeoVelocityAlertTitle(), message: Preference.getCheckGeoVelocityAlertMessage(), preferredStyle: .alert)
                if Preference.getCheckGeoVelocityAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                        subCheck(13)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                } else {
                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                        exit(-141)
                    }))
                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                    } else {
                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                    }
                }
            })
            return true
        }
        return false
    }
    
    static func checkBehaviourAnalysis() -> Bool {
        if Preference.getCheckBehaviourAnalysis() {
            isSuspiciousBehavior()
            return true
        }
        return false
    }
    
    
    private static func isEmulator() -> Bool {
        let deviceName = UIDevice.current.name
        if deviceName.contains("Simulator") {
            return true
        }
        let deviceModel = UIDevice.current.model
        if deviceModel.hasPrefix("Simulator") {
            return true
        }
        let systemName = UIDevice.current.systemName
        if systemName == "Simulator" {
            return true
        }
        #if targetEnvironment(simulator)
        return true
        #else
        #endif
        return false
    }
    
    private static func isRooted() -> Bool {
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: "/Applications/Cydia.app") ||
            fileManager.fileExists(atPath: "/Library/MobileSubstrate/MobileSubstrate.dylib") ||
            fileManager.fileExists(atPath: "/bin/bash") ||
            fileManager.fileExists(atPath: "/usr/sbin/sshd") ||
            fileManager.fileExists(atPath: "/etc/apt") ||
            fileManager.fileExists(atPath: "/private/var/lib/apt/") ||
            fileManager.fileExists(atPath: "/Applications/FakeApp.app") {
            return true
        }
        
        let testPath = "/private/" + UUID().uuidString
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            // Could not write outside sandbox
        }
        
        return false
    }
    
    private static func isTempering() -> Bool {
        return false
    }
    
    private static func isDebugging() -> Bool {
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size

        let result = sysctl(&name, UInt32(name.count), &info, &size, nil, 0)
        
        if result == 0 {
            return (info.kp_proc.p_flag & P_TRACED) != 0
        } else {
            return false
        }
    }
    
    private static func isHooked() -> Bool {
        let suspiciousLibraries = [
            "FridaGadget",
            "libsubstrate.dylib",
            "libcycript.dylib",
            "cyinject.dylib",
            "MobileSubstrate.dylib",
            "SSLKillSwitch.dylib",
            "CydiaSubstrate",
            "TweakInject",
            "0Shadow",
            "shadow.dylib"
        ]
        
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                for library in suspiciousLibraries {
                    if name.lowercased().contains(library.lowercased()) {
                        return true
                    }
                }
            }
        }
        return false
    }
    
    private static func isScreenCasting() -> Bool {
        return checkForExternalScreen()
    }
    
    @objc static func screenDidConnect(notification: Notification) {
        _ = checkScreenCasting()
    }
    
    // Called when a screen is disconnected
    @objc static func screenDidDisconnect(notification: Notification) {
        _ = checkScreenCasting()
    }
    
    private static func checkForExternalScreen() -> Bool {
        let screens = UIScreen.screens
        if screens.count > 1 {
            return true
        } else {
            return false
        }
    }
    
    private static func isScreenOverlay() -> Bool {
        return false
    }
    
    private static func isCallForwarded() -> Bool {
        return false
    }
    
    private static func isMultipleLogin() -> Bool {
        return false
    }
    
    private static func isSimSwap() -> Bool {
        guard let savedSimInfo: [String: [String: String]]? = SecureUserDefaultsSS.shared.value(forKey: "SavedSIMInfo") else {
            let simInfo = getSIMInfo()
            SecureUserDefaultsSS.shared.set(simInfo, forKey: "SavedSIMInfo")
            return false
        }
        let currentSimInfo = getSIMInfo()
        return savedSimInfo != currentSimInfo
    }
    
    private static func getSIMInfo() -> [String: [String: String]] {
        let networkInfo = CTTelephonyNetworkInfo()
        var simData: [String: [String: String]] = [:]
        
        if let carriers = networkInfo.serviceSubscriberCellularProviders {
            for (key, carrier) in carriers {
                let carrierName = carrier.carrierName ?? "Unknown"
                let mobileCountryCode = carrier.mobileCountryCode ?? "Unknown"
                let mobileNetworkCode = carrier.mobileNetworkCode ?? "Unknown"
                let isoCountryCode = carrier.isoCountryCode ?? "Unknown"
                
                simData[key] = [
                    "carrierName": carrierName,
                    "mobileCountryCode": mobileCountryCode,
                    "mobileNetworkCode": mobileNetworkCode,
                    "isoCountryCode": isoCountryCode
                ]
            }
        }
        return simData
    }
    
    private static func isGeovelocityDetected() -> Bool {
        return false
    }
    
    private static func isSuspiciousBehavior() {
        let data = collectDeviceAttributes()
//        print("DATA COLLECT: \(data)")
        DispatchQueue.global().async{
            SecurityShield.postDataWithCookiesAndUserAgent(from: URL(string: Preference.getDomainOpr() + "data_capture")!, parameter: data) { data, response, error in
                let response = response as? HTTPURLResponse
                if response?.statusCode != 200 || error != nil {
                    return
                }
                if let data = data, let responseString = String(data: data, encoding: .utf8) {
                    if !responseString.isEmpty {
//                        print("RESPON ANOMALI : \(responseString)")
                        if responseString == "ANOMALY_DETECTED" {
                            DispatchQueue.main.async(execute: {
                                let alert = SSLibAlertController(title: Preference.getCheckBehaviourAnalysisAlertTitle(), message: Preference.getCheckBehaviourAnalysisAlertMessage(), preferredStyle: .alert)
                                if Preference.getCheckBehaviourAnalysisAction() == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: {_ in
                                        subCheck(14)
                                    }))
                                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                                    } else {
                                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                                    }
                                } else {
                                    alert.addAction(UIAlertAction(title: "Exit", style: UIAlertAction.Style.default, handler: {_ in
                                        exit(-141)
                                    }))
                                    if UIApplication.shared.visibleViewController?.navigationController != nil {
                                        UIApplication.shared.visibleViewController?.navigationController?.present(alert, animated: true, completion: nil)
                                    } else {
                                        UIApplication.shared.visibleViewController?.present(alert, animated: true, completion: nil)
                                    }
                                }
                            })
                        }
                    }
                }
            }
        }
    }
    
    private static func sendShieldErrorLog(code: Int) {
        var data = collectDeviceAttributes()
        data["security_shield"] = "\(code)"
        if let jsonData = try? JSONSerialization.data(withJSONObject: data, options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            let me: String! = SecureUserDefaultsSS.shared.value(forKey: "me") ?? ""
            let tmessage = TMessageSS()
            tmessage.mCode = "SSG"
            tmessage.mStatus = CoreMessage_TMessageUtil.getTID()
            tmessage.mPIN = me
            tmessage.mBodies["A112"] = jsonString
            _ = Service.write(message: tmessage)
        }
    }
    
    private static let vers = "5.0.52"
    private var currentLocation: CLLocation?
    private static func collectDeviceAttributes() -> [String: Any] {
        var params: [String: Any] = [:]

        // User and session
        let me: String? = SecureUserDefaultsSS.shared.value(forKey: "me")
        let sesId: String? = Preference.getConnectionID()
        params["f_pin"] = me
        params["session_id"] = sesId

        // App info (replace with your preferences retrieval)
        params["api"] = Preference.getAccount()
        params["app_id"] = Preference.getAppId()
        params["lib_version"] = vers
        params["app_version"] = vers

        // Network Info
        let (netType, netTypeName) = getNetworkType()
        let (operatorCode, operatorName) = getCarrierInfo()
        let (wifiStatus, wifiIp, wifiSsid, wifiBssid) = getWifiInfo()
        params["network_type"] = netType
        params["network_type_name"] = netTypeName
        params["network_operator"] = operatorCode
        params["network_operator_name"] = operatorName
        params["wifi_ssid"] = wifiSsid
        params["wifi_bssid"] = wifiBssid
        params["wifi_adapter"] = wifiStatus
        params["wifi_ip"] = wifiIp
        

        // IP Address
        params["ip_addressv4"] = getIPAddress(useIPv4: true)
        params["ip_address"] = getIPAddress(useIPv4: false)

        // GPS / location
        let semaphore = DispatchSemaphore(value: 0)
        
        DispatchQueue.main.async {
            LocationFetcher.shared.getCurrentLocation { coordinate, score in
                var long = "0"
                var lat = "0"
                if let coord = coordinate {
                    long = "\(coord.longitude)"
                    lat = "\(coord.latitude)"
                }
//                print("Latitude: \(lat), Longitude: \(long)")
                params["latitude"] = lat
                params["longitude"] = long
                semaphore.signal()
            }
        }
        
        _ = semaphore.wait(timeout: .now() + 10.0)

        // iOS doesn't have an Android ID; use identifierForVendor
        params["ios_identifier"] = UIDevice.current.identifierForVendor?.uuidString ?? ""

        // Device attributes
        let device = UIDevice.current
        params["device_NAME"] = device.name
        params["device_MODEL"] = device.model
        params["device_SYSTEM_NAME"] = device.systemName
        params["device_SYSTEM_VERSION"] = device.systemVersion
        params["device_IDENTIFIER_FOR_VENDOR"] = device.identifierForVendor?.uuidString ?? ""

        return getSimData(params: params)
    }
    
    private static func getSimData(params: [String: Any] = [:]) -> [String: Any] {
        var params = params
        var simArray: [[String: Any]] = []

        let networkInfo = CTTelephonyNetworkInfo()

        if #available(iOS 12.0, *) {
            if let carriers = networkInfo.serviceSubscriberCellularProviders {
                for (key, carrier) in carriers {
                    var simInfo: [String: Any] = [:]
                    simInfo["carrier_name"] = carrier.carrierName ?? ""
                    simInfo["mcc"] = carrier.mobileCountryCode ?? ""
                    simInfo["mnc"] = carrier.mobileNetworkCode ?? ""
                    simInfo["sim_slot"] = key // This is not a true "slot", but the key used internally
                    simArray.append(simInfo)
                }
            }
        } else {
            if let carrier = networkInfo.subscriberCellularProvider {
                var simInfo: [String: Any] = [:]
                simInfo["carrier_name"] = carrier.carrierName ?? ""
                simInfo["mcc"] = carrier.mobileCountryCode ?? ""
                simInfo["mnc"] = carrier.mobileNetworkCode ?? ""
                simInfo["sim_slot"] = "default"
                simArray.append(simInfo)
            }
        }
        params["sim_data"] = simArray

        return params
    }
    
    private static func getNetworkType() -> (type: String, name: String) {
        let monitor = NWPathMonitor()
        var networkType = ""
        var networkTypeName = ""
        
        let semaphore = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { path in
            if path.usesInterfaceType(.wifi) {
                networkType = "1" // Corresponds to TYPE_WIFI in Android
                networkTypeName = "WIFI"
            } else if path.usesInterfaceType(.cellular) {
                networkType = "0" // Corresponds to TYPE_MOBILE
                networkTypeName = "MOBILE"
            } else {
                networkType = "-1"
                networkTypeName = "UNKNOWN"
            }
            semaphore.signal()
            monitor.cancel()
        }
        let queue = DispatchQueue(label: "NetworkMonitor")
        monitor.start(queue: queue)
        semaphore.wait()
        
        return (networkType, networkTypeName)
    }
    
    private static func getCarrierInfo() -> (operatorCode: String, operatorName: String) {
        let networkInfo = CTTelephonyNetworkInfo()
        
        var carrierCode = ""
        var carrierName = ""
        
        if #available(iOS 12.0, *) {
            if let carriers = networkInfo.serviceSubscriberCellularProviders {
                for (_, carrier) in carriers {
                    carrierCode = (carrier.mobileCountryCode ?? "") + (carrier.mobileNetworkCode ?? "")
                    carrierName = carrier.carrierName ?? ""
                    break // Just use the first one
                }
            }
        } else {
            if let carrier = networkInfo.subscriberCellularProvider {
                carrierCode = (carrier.mobileCountryCode ?? "") + (carrier.mobileNetworkCode ?? "")
                carrierName = carrier.carrierName ?? ""
            }
        }
        
        return (carrierCode, carrierName)
    }
    
    private static func getWifiInfo() -> (adapter: String, ip: String, ssid: String, bssid: String) {
        var adapterStatus = "Off"
        var ipAddress = ""
        var ssid = ""
        var bssid = ""
        
        // Get IP Address
        if let interfaces = CNCopySupportedInterfaces() as NSArray? {
            for interfaceName in interfaces {
                if let unsafeInterfaceData = CNCopyCurrentNetworkInfo(interfaceName as! CFString) as NSDictionary? {
                    ssid = unsafeInterfaceData["SSID"] as? String ?? ""
                    bssid = unsafeInterfaceData["BSSID"] as? String ?? ""
                    adapterStatus = "Connected"
                    break
                }
            }
        }
        
        if ssid.isEmpty {
            adapterStatus = "Not Connected"
        }

        ipAddress = getWiFiIPAddress() ?? ""

        return (adapterStatus, ipAddress, ssid, bssid)
    }

    private static func getWiFiIPAddress() -> String? {
        var address: String?

        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return nil }

        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            let addrFamily = interface.ifa_addr.pointee.sa_family

            if addrFamily == UInt8(AF_INET) || addrFamily == UInt8(AF_INET6) {
                let name = String(cString: interface.ifa_name)
                if name == "en0" { // en0 is Wi-Fi
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len),
                                &hostname, socklen_t(hostname.count),
                                nil, socklen_t(0), NI_NUMERICHOST)
                    address = String(cString: hostname)
                    break
                }
            }
        }

        freeifaddrs(ifaddr)
        return address
    }
    
    private static func getIPAddress(useIPv4: Bool) -> String {
        var address: String = ""

        var ifaddr: UnsafeMutablePointer<ifaddrs>? = nil
        if getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr {
            for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
                let interface = ptr.pointee
                let addrFamily = interface.ifa_addr.pointee.sa_family

                if addrFamily == UInt8(AF_INET) || addrFamily == UInt8(AF_INET6) {
                    let name = String(cString: interface.ifa_name)
                    if name == "en0" || name == "pdp_ip0" {
                        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                        let result = getnameinfo(
                            interface.ifa_addr,
                            socklen_t(interface.ifa_addr.pointee.sa_len),
                            &hostname,
                            socklen_t(hostname.count),
                            nil,
                            socklen_t(0),
                            NI_NUMERICHOST
                        )

                        if result == 0 {
                            let ip = String(cString: hostname)
                            let isIPv4 = ip.contains(":") == false
                            if useIPv4 && isIPv4 {
                                address = ip
                                break
                            } else if !useIPv4 && !isIPv4 {
                                // Remove IPv6 scope if present
                                let cleanIPv6 = ip.split(separator: "%").first.map(String.init) ?? ip
                                address = cleanIPv6.uppercased()
                                break
                            }
                        }
                    }
                }
            }
            freeifaddrs(ifaddr)
        }

        return address
    }
}

private class LocationFetcher: NSObject, CLLocationManagerDelegate {
    static var shared = LocationFetcher()
    private var manager: CLLocationManager?
    private var completion: ((CLLocationCoordinate2D?, Int) -> Void)?
    let motionMgr = CMMotionActivityManager()
    
    func motionSnapshot(_ done: @escaping (CMMotionActivity?) -> Void) {
        guard CMMotionActivityManager.isActivityAvailable() else {
            done(nil)
            return
        }
        let now = Date()
        motionMgr.queryActivityStarting(from: now.addingTimeInterval(-120), to: now, to: .main) { acts, _ in
            done(acts?.last)
        }
    }
    
    func getCurrentLocation(completion: @escaping (CLLocationCoordinate2D?, Int) -> Void) {
        self.completion = completion
        self.manager = CLLocationManager()
        self.manager?.delegate = self
        self.manager?.desiredAccuracy = kCLLocationAccuracyBest
        self.manager?.requestWhenInUseAuthorization()
        
        if CLLocationManager.locationServicesEnabled() {
            self.manager?.requestLocation()
        } else {
            completion(nil, 0)
        }
    }
    
    // MARK: - CLLocationManagerDelegate
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        motionSnapshot { snap in
            let (gpsScore, gpsReasons) = FakeGps.movementAndAccuracy(prev: locations.first, curr: locations.last!, motion: snap)
            self.completion?(locations.last?.coordinate, gpsScore)
        }
//        cleanup()
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        print("Error: \(error.localizedDescription)")
        completion?(nil, 0)
        cleanup()
    }
    
    private func cleanup() {
        manager?.stopUpdatingLocation()
        manager?.delegate = nil
        manager = nil
        completion = nil
    }
    
    enum FakeGps {
        static func movementAndAccuracy(prev: CLLocation?, curr: CLLocation, motion: CMMotionActivity?) -> (Int, [String]) {
            var score = 0
            var reasons: [String] = []
            
            // Accuracy check
            if curr.horizontalAccuracy > 200 {
                score += 10
                reasons.append("Low accuracy (>200m).")
            }
            
            // Movement checks
            if let p = prev {
                let dt = curr.timestamp.timeIntervalSince(p.timestamp)
                if dt >= 3 {
                    let d = curr.distance(from: p)
                    let v = d / dt
                    let vRep = curr.speed > 0 ? Double(curr.speed) : v
                    
                    if v > 150 && vRep < 10 {
                        score += 40
                        reasons.append("Unrealistic jump vs reported speed.")
                    }
                    
                    if v > 350 {
                        score += 60
                        reasons.append("Physically implausible speed (>350 m/s).")
                    }
                    
                    if curr.horizontalAccuracy <= 8 && d > 1000 {
                        score += 20
                        reasons.append("High accuracy but >1 km jump.")
                    }
                    
                    if p.courseAccuracy >= 0 && curr.courseAccuracy >= 0 {
                        let delta = abs(curr.course - p.course)
                        if delta < 1 && d > 3000 {
                            score += 10
                            reasons.append("Near-zero course jitter over long distance.")
                        }
                    }
                    
                    // NEW: unnatural smoothness
                    let speedDiff = abs(curr.speed - Double(v))
                    if speedDiff < 0.5 && d > 100 {
                        score += 10
                        reasons.append("Unnaturally smooth trajectory.")
                    }
                }
            }
            
            // Motion vs GPS mismatch
            if let m = motion {
                let moving = (m.walking || m.running || m.cycling || m.automotive)
                if !moving && curr.speed > 8 {
                    score += 20
                    reasons.append("High speed while motion reports stationary.")
                }
            }
            
            // Timezone mismatch check
            let deviceTZ = TimeZone.current
            let gpsTZ = TimeZone(secondsFromGMT: Int(curr.timestamp.timeIntervalSince1970)) // heuristic only
            if let gpsTZ = gpsTZ, gpsTZ.secondsFromGMT() != deviceTZ.secondsFromGMT() {
                score += 5
                reasons.append("Timezone mismatch with GPS region (heuristic).")
            }
            
            return (min(100, score), reasons)
        }
    }
}

private class Service {
    static func writeSync(message: TMessageSS, timeout: Int = 15 * 1000) -> TMessageSS? {
        if !API.bInetConnAvailable() || API.nGetCLXConnState() == 0 {
            return nil
        }
        do {
            if let data = try API.sGetResponse(sRequest: message.pack(), lTimeout: timeout, bKeepTOResp: true) {
                let response = TMessageSS(data: data)
                return response
            }
        } catch {
            print(error)
        }
        return nil
    }
    
    static func write(message: TMessageSS, timeout: Int = 15 * 1000) -> String? {
        do {
            if !API.bInetConnAvailable() || API.nGetCLXConnState() == 0 {
                return nil
            }
            //print(">> SENDING MESSAGE >> ", message.toLogString())
            if message.getMedia().count == 0 {
                if let data = try API.sSend(sData: message.pack(), nPriority: 1, lTimeout: timeout) {
                    //print("<< RESPONSE MESSAGE << ", data)
                    return data
                }
            }
            // media
            if let data = try API.sSend(abData: message.toBytes(), nPriority: 2, lTimeout: timeout) {
                //print("<< RESPONSE MESSAGE << ", data)
                return data
            }
        } catch {
            //print(error)
        }
        return nil
    }
}

private class Preference {
    static func setConnectionID(value: String) {
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CONNECTION_ID)
    }

    static func getConnectionID() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CONNECTION_ID) {
            return value
        }
        return ""
    }
    static func getAppId() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_USER_APP_ID) {
            return value
        }
        return ""
    }
    
    static func setAppId(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_USER_APP_ID)
    }
    
    static func getAccount() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_USER_ACCOUNT) {
            return value
        }
        return ""
    }
    
    static func setAccount(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_USER_ACCOUNT)
    }
    
    static func setDomainOpr(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_DOMAIN_OPR)
    }
    
    static func getDomainOpr() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_DOMAIN_OPR) {
            return value
        }
        return "https://nexilis.io/"
    }
    
    static func setIpPortOpr(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_IP_PORT_OPR)
    }
    
    static func getIpOpr() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_IP_PORT_OPR) {
            return value
        }
        return "34.101.172.194:42823"
    }
    
    /**
     * Keylogger
     */
    static func setPreventKeylogger(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER)
    }
    
    static func getPreventKeylogger() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER) {
            return value
        }
        return false
    }
    static func setPreventKeyloggerAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ACTION)
    }
    
    static func getPreventKeyloggerAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ACTION) {
            return value
        }
        return "0"
    }
    static func setKeyloggerAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_TITLE)
    }
    
    static func getKeyloggerAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_title
            }
            return value
        }
        return PreferencesKey.ss_screenshare_title
    }
    static func setKeyloggerAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_MESSAGE)
    }
    
    static func getKeyloggerAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_warning
            }
            return value
        }
        return PreferencesKey.ss_screenshare_warning
    }
    /**
     * Screen Capture
     */
    static func setPreventScreenCapture(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE)
    }
    
    static func getPreventScreenCapture() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE) {
            return value
        }
        return false
    }
    static func setPreventScreenCaptureAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ACTION)
    }
    
    static func getPreventScreenCaptureAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckScreenCaptureAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_TITLE)
    }
    
    static func getCheckScreenCaptureAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_title
            }
            return value
        }
        return PreferencesKey.ss_screenshare_title
    }
    static func setScreenCaptureAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_MESSAGE)
    }
    
    static func getScreenCaptureAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_warning
            }
            return value
        }
        return PreferencesKey.ss_screenshare_warning
    }
    /**
     * Emulator
     */
    static func setCheckEmulator(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR)
    }
    
    static func getCheckEmulator() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR) {
            return value
        }
        return false
    }
    static func setCheckEmulatorAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR_ACTION)
    }
    
    static func getCheckEmulatorAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckEmulatorAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_TITLE)
    }
    
    static func getCheckEmulatorAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_emulator_title
            }
            return value
        }
        return PreferencesKey.ss_emulator_title
    }
    static func setCheckEmulatorAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_MESSAGE)
    }
    
    static func getCheckEmulatorAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_emulator_continue
            }
            return value
        }
        return PreferencesKey.ss_emulator_continue
    }
    
    /**
     * Root/Jailbreak Detection
     */
    static func setCheckRooted(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED)
    }
    
    static func getCheckRooted() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED) {
            return value
        }
        return false
    }
    static func setCheckRootedAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION)
    }
    
    static func getCheckRootedAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckRootedAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_TITLE)
    }
    
    static func getCheckRootedAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_rooted_title
            }
            return value
        }
        return PreferencesKey.ss_rooted_title
    }
    static func setCheckRootedAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_MESSAGE)
    }
    
    static func getCheckRootedAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_rooted_warning
            }
            return value
        }
        return PreferencesKey.ss_rooted_warning
    }
    
    /**
     * Outdated OS Detection
     */
    static func setCheckOutdatedOs(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_OUTDATED_OS)
    }
    
    static func getCheckOutdatedOs() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_OUTDATED_OS) {
            return value
        }
        return false
    }
    static func setCheckOutdatedOsAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION)
    }
    
    static func getCheckOutdatedOsAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckOutdatedOsAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_TITLE)
    }
    
    static func getCheckOutdatedOsAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_os_not_supported_title
            }
            return value
        }
        return PreferencesKey.ss_os_not_supported_title
    }
    static func setCheckOutdatedOsAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_MESSAGE)
    }
    
    static func getCheckOutdatedOsAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_os_not_supported_continue
            }
            return value
        }
        return PreferencesKey.ss_os_not_supported_continue
    }
    static func setMinimumOsVersion(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MINIMUM_OS_VERSION)
    }
    
    static func getMinimumOsVersion() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MINIMUM_OS_VERSION) {
            return value
        }
        return "14"
    }
    
    /**
     * Tempering Detection
     */
    static func setCheckTempering(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING)
    }
    
    static func getCheckTempering() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING) {
            return value
        }
        return false
    }
    static func setCheckTemperingAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING_ACTION)
    }
    
    static func getCheckTemperingAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckTemperingAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_TITLE)
    }
    
    static func getCheckTemperingAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_tempering_title
            }
            return value
        }
        return PreferencesKey.ss_tempering_title
    }
    static func setCheckTemperingAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_MESSAGE)
    }
    
    static func getCheckTemperingAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_tempering_warning
            }
            return value
        }
        return PreferencesKey.ss_tempering_warning
    }
    
    /**
     * Debugging Detection
     */
    static func setCheckDebugging(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING)
    }
    
    static func getCheckDebugging() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING) {
            return value
        }
        return false
    }
    static func setCheckDebuggingAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING_ACTION)
    }
    
    static func getCheckDebuggingAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckDebuggingAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_TITLE)
    }
    
    static func getCheckDebuggingAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_title
            }
            return value
        }
        return PreferencesKey.ss_debugging_title
    }
    static func setCheckDebuggingAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_MESSAGE)
    }
    
    static func getCheckDebuggingAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_warning
            }
            return value
        }
        return PreferencesKey.ss_debugging_warning
    }
    
    /**
     * Screen Casting
     */
    static func setCheckScreenCasting(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING)
    }
    
    static func getCheckScreenCasting() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING) {
            return value
        }
        return false
    }
    static func setCheckScreenCastingAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ACTION)
    }
    
    static func getCheckScreenCastingAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckScreenCastingAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_TITLE)
    }
    
    static func getCheckScreenCastingAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_title
            }
            return value
        }
        return PreferencesKey.ss_debugging_title
    }
    static func setCheckScreenCastingAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_MESSAGE)
    }
    
    static func getCheckScreenCastingAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_warning
            }
            return value
        }
        return PreferencesKey.ss_debugging_warning
    }
    
    /**
     * Screen Overlay
     */
    static func setCheckScreenOverlay(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY)
    }
    
    static func getCheckScreenOverlay() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY) {
            return value
        }
        return false
    }
    static func setCheckScreenOverlayAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ACTION)
    }
    
    static func getCheckScreenOverlayAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckScreenOverlayAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_TITLE)
    }
    
    static func getCheckScreenOverlayAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenoverlay_title
            }
            return value
        }
        return PreferencesKey.ss_screenoverlay_title
    }
    static func setCheckScreenOverlayAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_MESSAGE)
    }
    
    static func getCheckScreenOverlayAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenoverlay_continue
            }
            return value
        }
        return PreferencesKey.ss_screenoverlay_continue
    }
    
    /**
     * Call Redirection Detection
     */
    static func setCheckCallForward(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD)
    }
    
    static func getCheckCallForward() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD) {
            return value
        }
        return false
    }
    static func setCheckCallForwardAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ACTION)
    }
    
    static func getCheckCallForwardAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckCallForwardAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_TITLE)
    }
    
    static func getCheckCallForwardAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_callforward_title
            }
            return value
        }
        return PreferencesKey.ss_callforward_title
    }
    static func setCheckCallForwardAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_MESSAGE)
    }
    
    static func getCheckCallForwardAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_callforward_continue
            }
            return value
        }
        return PreferencesKey.ss_callforward_continue
    }
    
    /**
     * Multiple Login Detection
     */
    static func setCheckMultipleLogin(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN)
    }
    
    static func getCheckMultipleLogin() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN) {
            return value
        }
        return false
    }
    static func setCheckMultipleLoginAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ACTION)
    }
    
    static func getCheckMultipleLoginAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckMultipleLoginAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_TITLE)
    }
    
    static func getCheckMultipleLoginAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_multiple_login_title
            }
            return value
        }
        return PreferencesKey.ss_multiple_login_title
    }
    static func setCheckMultipleLoginAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_MESSAGE)
    }
    
    static func getCheckMultipleLoginAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_multiple_login_warning
            }
            return value
        }
        return PreferencesKey.ss_multiple_login_warning
    }
    
    /**
     * SIM Swap Detection
     */
    static func setCheckSimSwap(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP)
    }
    
    static func getCheckSimSwap() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP) {
            return value
        }
        return false
    }
    static func setCheckSimSwapAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ACTION)
    }
    
    static func getCheckSimSwapAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckSimSwapAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_TITLE)
    }
    
    static func getCheckSimSwapAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_simswap_title
            }
            return value
        }
        return PreferencesKey.ss_simswap_title
    }
    static func setCheckSimSwapAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_MESSAGE)
    }
    
    static func getCheckSimSwapAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_simswap_warning
            }
            return value
        }
        return PreferencesKey.ss_simswap_warning
    }
    
    /**
     * Geo-Velocity Checks
     */
    static func setCheckGeoVelocity(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY)
    }
    
    static func getCheckGeoVelocity() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY) {
            return value
        }
        return false
    }
    static func setCheckGeoVelocityAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ACTION)
    }
    
    static func getCheckGeoVelocityAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckGeoVelocityAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_TITLE)
    }
    
    static func getCheckGeoVelocityAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_geo_velocity_title
            }
            return value
        }
        return PreferencesKey.ss_geo_velocity_title
    }
    static func setCheckGeoVelocityAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_MESSAGE)
    }
    
    static func getCheckGeoVelocityAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_geo_velocity_warning
            }
            return value
        }
        return PreferencesKey.ss_geo_velocity_warning
    }
    
    /**
     * Behavioral Anomaly Detection
     */
    static func setCheckBehaviourAnalysis(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS)
    }
    
    static func getCheckBehaviourAnalysis() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS) {
            return value
        }
        return false
    }
    static func setCheckBehaviourAnalysisAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ACTION)
    }
    
    static func getCheckBehaviourAnalysisAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckBehaviourAnalysisAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_TITLE)
    }
    
    static func getCheckBehaviourAnalysisAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_behaviour_anomaly_title
            }
            return value
        }
        return PreferencesKey.ss_behaviour_anomaly_title
    }
    static func setCheckBehaviourAnalysisAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_MESSAGE)
    }
    
    static func getCheckBehaviourAnalysisAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_behaviour_anomaly_warning
            }
            return value
        }
        return PreferencesKey.ss_behaviour_anomaly_warning
    }
    
    /**
     * Hooked Detection
     */
    static func setCheckHooked(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED)
    }
    
    static func getCheckHooked() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED) {
            return value
        }
        return false
    }
    static func setCheckHookedAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED_ACTION)
    }
    
    static func getCheckHookedAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckHookedAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_TITLE)
    }
    
    static func getCheckHookedAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_hooked_title
            }
            return value
        }
        return PreferencesKey.ss_hooked_title
    }
    static func setCheckHookedAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_MESSAGE)
    }
    
    static func getCheckHookedAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_hooked_warning
            }
            return value
        }
        return PreferencesKey.ss_hooked_warning
    }
}

private class PreferencesKey {
    static let SECURITY_SHIELD_ALERT_EXIT = "0"
    static let SECURITY_SHIELD_ALERT_CONTINUE = "1"
    
    static let ERR121 = "121:Emulator detected"
    static let ERR122 = "122:Malware detected"
    static let ERR123 = "123:USB/WiFi debugging detected"
    static let ERR124 = "124:Cloned app detected"
    static let ERR125 = "125:Call forwarding detected"
    static let ERR126 = "126:Screen sharing detected"
    static let ERR127 = "127:OS Version not supported"
    static let ERR128 = "128:Application backup detected"
    static let ERR129 = "129:Failed security reasons"
    static let ERR130 = "130:Tampering detected"
    static let ERR131 = "131:SIM Swap detected"
    static let ERR132 = "132:Behavioral Anomaly detected"
    
    static let SS_CONNECTION_ID = "ss_connection_id"
    
    static let SS_USER_APP_ID = "ss_user_app_id"
    static let SS_USER_ACCOUNT = "ss_user_account"
    static let SS_DOMAIN_OPR = "domain_opr"
    static let SS_IP_PORT_OPR = "ip_opr"
    
    static let SS_CHECK_KEYLOGGER = "ss_check_keylogger"
    static let SS_CHECK_KEYLOGGER_ACTION = "ss_check_keylogger_action"
    static let SS_CHECK_KEYLOGGER_ALERT_TITLE = "ss_check_keylogger_alert_title"
    static let SS_CHECK_KEYLOGGER_ALERT_MESSAGE = "ss_check_keylogger_alert_message"

    static let SS_CHECK_SCREEN_CAPTURE = "ss_check_screen_capture"
    static let SS_CHECK_SCREEN_CAPTURE_ACTION = "ss_check_screen_capture_action"
    static let SS_CHECK_SCREEN_CAPTURE_ALERT_TITLE = "ss_check_screen_capture_alert_title"
    static let SS_CHECK_SCREEN_CAPTURE_ALERT_MESSAGE = "ss_check_screen_capture_alert_message"
    static let ss_screenshare_title = "Screen Sharing Detected!"
    static let ss_screenshare_warning = "We are sorry for the inconvenience. For security reasons this app is not allowed to cast/share screen display. The application will automatically stop.<br><br>To try again, please stop the screen casting/sharing."
        
    
    static let SS_CHECK_EMULATOR = "ss_check_emulator"
    static let SS_CHECK_EMULATOR_ACTION = "ss_check_emulator_action"
    static let SS_CHECK_EMULATOR_ALERT_TITLE = "ss_check_emulator_alert_title"
    static let SS_CHECK_EMULATOR_ALERT_MESSAGE = "ss_check_emulator_alert_message"
    static let ss_emulator_title = "Emulator Detected!"
    static let ss_emulator_continue = "We are sorry for the inconvenience. For security reasons this app is not allowed to run on an emulator."
    
    static let SS_CHECK_ROOTED = "ss_check_rooted"
    static let SS_CHECK_ROOTED_ACTION = "ss_check_rooted_action"
    static let SS_CHECK_ROOTED_ALERT_TITLE = "ss_check_rooted_alert_title"
    static let SS_CHECK_ROOTED_ALERT_MESSAGE = "ss_check_rooted_alert_message"
    static let ss_rooted_title = "Root or Jailbreak Detected!"
    static let ss_rooted_warning = "The operating system on your device has been modified unauthorizedly(the root). The modification might compromise secure access to organizational resources such as email and documents.<br><br> %app_name% will not work on your device. Please reset/unroot your device or contact %app_name% customer center for further information. We apologize for the inconvenient."
    
    static let SS_CHECK_OUTDATED_OS = "ss_check_outdated_os"
    static let SS_CHECK_OUTDATED_OS_ACTION = "ss_check_outdated_os_action"
    static let SS_CHECK_OUTDATED_OS_ALERT_TITLE = "ss_check_outdated_os_alert_title"
    static let SS_CHECK_OUTDATED_OS_ALERT_MESSAGE = "ss_check_outdated_os_alert_message"
    static let SS_CHECK_MINIMUM_OS_VERSION = "ss_minimum_os_version"
    static let ss_os_not_supported_title = "Android Version Not Secure!"
    static let ss_os_not_supported_continue = "We are sorry for the inconvenience. This device's Android version has been deemed as no longer secure."
    
    static let SS_CHECK_TEMPERING = "ss_check_tempering"
    static let SS_CHECK_TEMPERING_ACTION = "ss_check_tempering_action"
    static let SS_CHECK_TEMPERING_ALERT_TITLE = "ss_check_tempering_alert_title"
    static let SS_CHECK_TEMPERING_ALERT_MESSAGE = "ss_check_tempering_alert_message"
    static let ss_tempering_title = "Tempering Detected!"
    static let ss_tempering_warning = "Our security shield has detected changes in the application that may indicate tempering, which could potentially lead to malware infection, data manipulation, and other risks. Please remove this apps and download from official Google Play Store."
    
    static let SS_CHECK_DEBUGGING = "ss_check_debugging"
    static let SS_CHECK_DEBUGGING_ACTION = "ss_check_debugging_action"
    static let SS_CHECK_DEBUGGING_ALERT_TITLE = "ss_check_debugging_alert_title"
    static let SS_CHECK_DEBUGGING_ALERT_MESSAGE = "ss_check_debugging_alert_message"
    static let ss_debugging_title = "Debugging Mode Detected!"
    static let ss_debugging_warning = "Your device running on debugging mode. Please disable it."
    
    static let SS_CHECK_SCREEN_CASTING = "ss_check_screen_casting"
    static let SS_CHECK_SCREEN_CASTING_ACTION = "ss_check_screen_casting_action"
    static let SS_CHECK_SCREEN_CASTING_ALERT_TITLE = "ss_check_screen_casting_alert_title"
    static let SS_CHECK_SCREEN_CASTING_ALERT_MESSAGE = "ss_check_screen_casting_alert_message"
    
    static let SS_CHECK_SCREEN_OVERLAY = "ss_check_screen_overlay"
    static let SS_CHECK_SCREEN_OVERLAY_ACTION = "ss_check_screen_overlay_action"
    static let SS_CHECK_SCREEN_OVERLAY_ALERT_TITLE = "ss_check_screen_overlay_alert_title"
    static let SS_CHECK_SCREEN_OVERLAY_ALERT_MESSAGE = "ss_check_screen_overlay_alert_message"
    static let ss_screenoverlay_title = "Screen Overlay Detected!"
    static let ss_screenoverlay_continue = "We are sorry for the inconvenience. For security reasons this app is not allowed to share screen overlay. Please stop the screen overlay in app setting."
    
    static let SS_CHECK_CALL_FORWARD = "ss_check_call_forward"
    static let SS_CHECK_CALL_FORWARD_ACTION = "ss_check_call_forward_action"
    static let SS_CHECK_CALL_FORWARD_ALERT_TITLE = "ss_check_call_forward_alert_title"
    static let SS_CHECK_CALL_FORWARD_ALERT_MESSAGE = "ss_check_call_forward_alert_message"
    static let ss_callforward_title = "Call Forwarding Detected!";
    static let ss_callforward_continue = "We are sorry for the inconvenience. For security reasons this app does not recommend allowing call forwarding to be active.";
    
    static let SS_CHECK_MULTIPLE_LOGIN = "ss_check_multiple_login"
    static let SS_CHECK_MULTIPLE_LOGIN_ACTION = "ss_check_multiple_login_action"
    static let SS_CHECK_MULTIPLE_LOGIN_ALERT_TITLE = "ss_check_multiple_login_alert_title"
    static let SS_CHECK_MULTIPLE_LOGIN_ALERT_MESSAGE = "ss_check_multiple_login_alert_message"
    static let ss_multiple_login_title = "Multiple Login Detected!"
    static let ss_multiple_login_warning = "We have detected multiple login attempts to your account from different devices or locations within a short period. This alert is designed to protect your account and ensure your security.<br><br> If you initiated these logins, no further action is required. However, if you did not authorize this activity, it is crucial to take immediate steps to safeguard your account. Unauthorized access may put your personal information at risk."
    
    static let SS_CHECK_SIM_SWAP = "ss_check_sim_swap"
    static let SS_CHECK_SIM_SWAP_ACTION = "ss_check_sim_swap_action"
    static let SS_CHECK_SIM_SWAP_ALERT_TITLE = "ss_check_sim_swap_alert_title"
    static let SS_CHECK_SIM_SWAP_ALERT_MESSAGE = "ss_check_sim_swap_alert_message"
    static let ss_simswap_title = "Sim Swap Detected!"
    static let ss_simswap_warning = "We noticed some unusual app behaviors and activities, including SimCard Swap on your device. If these actions were not initiated by you or you are unsure about any apps, please change your true number imediately."
    
    static let SS_CHECK_GEO_VELOCITY = "ss_check_geo_velocity"
    static let SS_CHECK_GEO_VELOCITY_ACTION = "ss_check_geo_velocity_action"
    static let SS_CHECK_GEO_VELOCITY_ALERT_TITLE = "ss_check_geo_velocity_alert_title"
    static let SS_CHECK_GEO_VELOCITY_ALERT_MESSAGE = "ss_check_geo_velocity_alert_message"
    static let ss_geo_velocity_title = "Geo Velocity Anomaly Detected!"
    static let ss_geo_velocity_warning = "Anomalies have been identified in the location check associated with your account. This warning is issued to inform you of significant irregularities in the expected location data. Immediate attention is required to address these anomalies, as they may impact your account's functionality, security, and overall user experience."

    static let SS_CHECK_BEHAVIOUR_ANALYSIS = "ss_check_behaviour_analysis"
    static let SS_CHECK_BEHAVIOUR_ANALYSIS_ACTION = "ss_check_behaviour_analysis_action"
    static let SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_TITLE = "ss_check_behaviour_analysis_alert_title"
    static let SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_MESSAGE = "ss_check_behaviour_analysis_alert_message"
    static let ss_behaviour_anomaly_title = "Behaviour Anomaly Detected!"
    static let ss_behaviour_anomaly_warning = "We have identified a significant anomaly in the behavior of your device. This notification serves as a precautionary measure, as unusual patterns can indicate potential security threats, unauthorized access, or software malfunctions that could compromise your data and overall device performance."
    
    static let SS_CHECK_HOOKED = "ss_check_hooked"
    static let SS_CHECK_HOOKED_ACTION = "ss_check_hooked_action"
    static let SS_CHECK_HOOKED_ALERT_TITLE = "ss_check_hooked_alert_title"
    static let SS_CHECK_HOOKED_ALERT_MESSAGE = "ss_check_hooked_alert_message"
    static let ss_hooked_title = "Hooked Detected!"
    static let ss_hooked_warning = "Our security shield has detected changes in the application that may indicate Hook or Anti Frida, which could potentially lead to malware infection, data manipulation, and other risks. Please remove this apps and download from official App Store."
}

private class SelfSignedURLSessionDelegate: NSObject, URLSessionTaskDelegate, URLSessionDataDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
            }
        }
    }
}

private class UtilsSS {
    private static let I_BB = 48   // 0
    private static let I_BBT_1 = 57 // 9
    private static let I_BAT_1 = 65 // A
    private static let I_BBT_2 = 90 // Z
    private static let I_BAT_2 = 97 // a
    private static let I_BA = 122  // z

    private static let IC_BB = 33   // !
    private static let IC_BBT_1 = 47 // /
    private static let IC_BAT_1 = 58 // :
    private static let IC_BBT_2 = 64 // @
    private static let IC_BAT_2 = 91 // [
    private static let IC_BBT_3 = 96 // @
    private static let IC_BAT_3 = 123 // [
    private static let IC_BA = 126  // `

    private static var icIGNORE = Set<Int>()

    private static func initIcIgnore() {
        icIGNORE.insert(10)// \r
        icIGNORE.insert(13)// \n
        icIGNORE.insert(32)// <space>
    }
    
    public static func decrypt(str: String) -> String {
        var arr: [Character]
        var iRandom = 0
        var sDecrypt: String
        iRandom = Int(str.substring(from: 0, to: 0)) ?? 0
        sDecrypt = getPalindrom(str: str.substring(from: 1, to: nil))
        arr = Array(sDecrypt)
        for i in 0..<arr.count {
            if (isSpecialChar(ch: arr[i])) {
                arr[i] = getBeforecChar(ch: arr[i], inc: iRandom)
            } else {
                arr[i] = getBeforeChar(ch: arr[i], inc: iRandom)
            }
        }
        return String(arr)
    }
    
    private static func isSpecialChar(ch: Character) -> Bool {
        let ch = Int(ch.asciiValue ?? 0)
        return (ch >= IC_BB && ch <= IC_BBT_1) || (ch >= IC_BAT_1 && ch <= IC_BBT_2) || (ch >= IC_BAT_2 && ch <= IC_BBT_3) || (ch >= IC_BAT_3 && ch <= IC_BA)
    }
    
    private static func getPalindrom(str: String) -> String {
        let arr: [Character] = Array(str)
        var arr2: [Character] = Array(arr)

        for i in 0..<arr.count {
            arr2[i] = arr[arr.count - (i + 1)]
        }
        return String(arr2)
    }
    
    private static func getBeforeChar(ch: Character, inc: Int) -> Character {
        if icIGNORE.isEmpty {
            initIcIgnore()
        }
        var iAscii = ch
        let iAsciiBefore = iAscii

        if (icIGNORE.contains(Int(iAscii.asciiValue ?? 0))) {
            return iAscii;
        }

        if Int(iAscii.asciiValue ?? 0) > I_BA || Int(iAscii.asciiValue ?? 0) < I_BB {
        } else {
            if !icIGNORE.contains(Int(iAscii.asciiValue ?? 0)) {
                iAscii = Character(UnicodeScalar(Int(iAscii.asciiValue ?? 0) - inc)!)
                if (I_BAT_1 > Int(iAscii.asciiValue ?? 0) && Int(iAsciiBefore.asciiValue ?? 0) >= I_BAT_1) {
                    iAscii = Character(UnicodeScalar((I_BBT_1 + 1) - (I_BAT_1 - Int(iAscii.asciiValue ?? 0)))!)
                }
                if (I_BAT_2 > Int(iAscii.asciiValue ?? 0) && Int(iAsciiBefore.asciiValue ?? 0) >= I_BAT_2) {
                    iAscii = Character(UnicodeScalar((I_BBT_2 + 1) - (I_BAT_2 - Int(iAscii.asciiValue ?? 0)))!)
                }
                if (Int(iAscii.asciiValue ?? 0) < I_BB) {
                    iAscii = Character(UnicodeScalar((I_BA + 1) + (Int(iAscii.asciiValue ?? 0) - I_BB))!)
                }
            }
        }
        return iAscii
    }
    
    private static func getBeforecChar(ch: Character, inc: Int) -> Character {
        var iAscii = ch
        let iAsciiBefore = iAscii
        if (Int(iAscii.asciiValue ?? 0) > IC_BA || Int(iAscii.asciiValue ?? 0) < IC_BB) {
        } else {
            iAscii = Character(UnicodeScalar(Int(iAscii.asciiValue ?? 0) - inc)!)
            if (Int(iAscii.asciiValue ?? 0) < IC_BB) {
                iAscii = Character(UnicodeScalar((IC_BA + 1) + (Int(iAscii.asciiValue ?? 0) - IC_BB))!)
                if (Int(iAscii.asciiValue ?? 0) < IC_BAT_3 && Int(iAscii.asciiValue ?? 0) > IC_BBT_3) {
                    iAscii = Character(UnicodeScalar((IC_BBT_3 + 1) - (IC_BAT_3 - Int(iAscii.asciiValue ?? 0)))!)
                }
            }
            if (IC_BAT_3 > Int(iAscii.asciiValue ?? 0) && Int(iAsciiBefore.asciiValue ?? 0) >= IC_BAT_3) {
                iAscii = Character(UnicodeScalar((IC_BBT_3 + 1) - (IC_BAT_3 - Int(iAscii.asciiValue ?? 0)))!)
            }
            if (IC_BAT_2 > Int(iAscii.asciiValue ?? 0) && Int(iAsciiBefore.asciiValue ?? 0) >= IC_BAT_2) {
                iAscii = Character(UnicodeScalar((IC_BBT_2 + 1) - (IC_BAT_2 - Int(iAscii.asciiValue ?? 0)))!)
            }
            if (IC_BAT_1 > Int(iAscii.asciiValue ?? 0) && Int(iAsciiBefore.asciiValue ?? 0) >= IC_BAT_1) {
                iAscii = Character(UnicodeScalar((IC_BBT_1 + 1) - (IC_BAT_1 - Int(iAscii.asciiValue ?? 0)))!)
            }
        }
        return iAscii
    }
}

extension String {
    func substring(from: Int?, to: Int?) -> String {
        if let start = from {
            guard start < self.count else {
                return ""
            }
        }
        
        if let end = to {
            guard end >= 0 else {
                return ""
            }
        }
        
        if let start = from, let end = to {
            guard end - start >= 0 else {
                return ""
            }
        }
        
        let startIndex: String.Index
        if let start = from, start >= 0 {
            startIndex = self.index(self.startIndex, offsetBy: start)
        } else {
            startIndex = self.startIndex
        }
        
        let endIndex: String.Index
        if let end = to, end >= 0, end < self.count {
            endIndex = self.index(self.startIndex, offsetBy: end + 1)
        } else {
            endIndex = self.endIndex
        }
        
        return String(self[startIndex ..< endIndex])
    }
}

extension UIColor {
    static var mainColorSS: UIColor {
        return renderColor(hex: "#046cfc")
    }
    
    static var blackDarkModeSS: UIColor {
        return renderColor(hex: "#262626")
    }
    
    private class func renderColor(hex: String) -> UIColor {
        var cString:String = hex.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()

        if (cString.hasPrefix("#")) {
            cString.remove(at: cString.startIndex)
        }

        if ((cString.count) != 6) {
            return UIColor.gray
        }

        var rgbValue:UInt64 = 0
        Scanner(string: cString).scanHexInt64(&rgbValue)

        return UIColor(
            red: CGFloat((rgbValue & 0xFF0000) >> 16) / 255.0,
            green: CGFloat((rgbValue & 0x00FF00) >> 8) / 255.0,
            blue: CGFloat(rgbValue & 0x0000FF) / 255.0,
            alpha: CGFloat(1.0)
        )
    }
}

extension UIApplication {
    static var appVersion: String? {
        return Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    }
    
    var rootViewController: UIViewController? {
        return UIApplication.shared.windows.filter {$0.isKeyWindow}.first?.rootViewController
    }
    
    var visibleViewController: UIViewController? {
        let keyWindow = UIApplication.shared.windows.filter {$0.isKeyWindow}.first
        if var topController = keyWindow?.rootViewController {
            while let presentedViewController = topController.presentedViewController {
                topController = presentedViewController
            }
            return topController
        }
        return nil
    }
}

extension UIImage {
    static func imageWithColorSS(color: UIColor, size: CGSize) -> UIImage? {
        let rect = CGRect(x: 0, y: 0, width: size.width, height: size.height)
        UIGraphicsBeginImageContextWithOptions(size, false, 0)
        color.setFill()
        UIRectFill(rect)
        guard let image: UIImage = UIGraphicsGetImageFromCurrentImageContext() else {
            return nil
        }
        UIGraphicsEndImageContext()
        return image
    }
}

private class TMessageSS {
    var mType: String = ""
    var mVersion: String = ""
    var mCode: String = ""
    var mStatus: String = ""
    var mPIN: String = ""
    var mL_PIN: String = ""
    var mBodies: [String: String] = [String: String]()
    private var mMedia:[UInt8] = [UInt8]()
    
    let C_HEADER:UnicodeScalar = UnicodeScalar(0x01)
    let C_ENTRY:UnicodeScalar = UnicodeScalar(0x02)
    let C_KEYVAL:UnicodeScalar = UnicodeScalar(0x03)
    let C_ARRAY:UnicodeScalar = UnicodeScalar(0x04)
    
    var S_HEADER: String = ""
    var S_ENTRY: String = ""
    var S_KEYVAL: String = ""
    var S_ARRAY: String = ""
    
    
    static let TYPE_SQLITE_ONLY =  "1"
    static let TYPE_ALL         =  "2"
    static let TYPE_NEED_ACK    =  "3"
    
    let ERRCOD = "A97"
    let MEDIA_LENGTH = "ML"
    let FILE_SIZE = "A53C"
    let IMEI = "Bb"
    let VERCOD = "Bd"
    
    func getCLMUserId() -> String {
        guard let me: String = SecureUserDefaultsSS.shared.value(forKey: "me") else {
            return ""
        }
        return me
    }
    
    init() {
        mVersion = "1.0.116"
        mBodies[IMEI] = getCLMUserId()
        mBodies[VERCOD] = "2.2.177"
    }
    
    init(data : String) {
        _ = unpack(data: data)
    }
    
    init(type: String, version: String, code: String,status: String, pin: String, l_pin: String, bodies:[String: String], media:  [UInt8]) {
        mType = type
        mVersion = version
        mCode = code
        mStatus = status
        mPIN = pin
        mL_PIN = l_pin
        mBodies = bodies
        mMedia = media
        mBodies[IMEI] = getCLMUserId()
        mBodies[VERCOD] = "2.2.177"
    }
    
    func clone(p_tmessage:TMessageSS) -> TMessageSS {
        return TMessageSS(
            type: p_tmessage.mType,
            version: p_tmessage.mVersion,
            code: p_tmessage.mCode,
            status: p_tmessage.mStatus,
            pin: p_tmessage.mPIN,
            l_pin: p_tmessage.mL_PIN,
            bodies: p_tmessage.mBodies,
            media: p_tmessage.mMedia
        )
    }
    
    func setMedia(media: [UInt8]) {
        mMedia = media
        mBodies[MEDIA_LENGTH] = String(media.count)
    }
    
    func getCode() -> String {
        return mCode
    }
    func getStatus() -> String {
        return mStatus
    }
    func getPIN() -> String {
        return mPIN
    }
    func getType() -> String {
        return mType
    }
    func getL_PIN() -> String {
        return mL_PIN
    }
    func getMedia() -> [UInt8] {
        return mMedia
    }
    func getBody(key : String) -> String {
        if let data = mBodies[key] {
            return data
        }
        else {
            return ""
        }
    }
    func getBody(key : String, default_value: String) -> String {
        if ((mBodies[key] == nil)) {
            return default_value
        } else if mBodies[key] == "null" {
            return default_value
        } else {
            return mBodies[key]!
        }
    }
    
    func getBodyAsInteger(key : String, default_value: Int) -> Int {
        if ((mBodies[key] == nil)) {
            return default_value
        } else if mBodies[key] == "null" {
            return default_value
        } else {
            return Int(mBodies[key]!)!
        }
    }
    func getBodyAsLong(key : String, default_value: CLong) -> CLong {
        if let body = mBodies[key] {
            if (body == "null") {
                return default_value
            }
            if (body == "nil") {
                return default_value
            }
            return (body as NSString).integerValue
            
        }
        else {
            return default_value
        }
    }
    
    func pack() -> String {
        if (S_HEADER.isEmpty) { S_HEADER.append(Character(C_HEADER)) }
        
        var data = ""
        data.append(mType)
        data.append(Character(C_HEADER))
        data.append(mVersion)
        data.append(Character(C_HEADER))
        data.append(mCode)
        data.append(Character(C_HEADER))
        data.append(mStatus)
        data.append(Character(C_HEADER))
        data.append(mPIN)
        data.append(Character(C_HEADER))
        data.append(mL_PIN)
        data.append(Character(C_HEADER))
        data.append(toString(body: mBodies))
        data.append(Character(C_HEADER))
        if let media = String(data: Data(getMedia()), encoding: .windowsCP1250) {
            data.append(media)
        }
        return data
        
    }
    
    
    func toBytes() -> [UInt8] {
        let data:String = pack()
        var result: [UInt8] = Array(data.utf8)
        if (!getMedia().isEmpty) {
            for index in 0...getMedia().count - 1 {
                result.append(getMedia()[index])
            }
        }
        return result
        
    }
    
    private func toString(body : [String: String]) -> String {
        if (S_ENTRY.isEmpty) { S_ENTRY.append(Character(C_ENTRY)) }
        if (S_KEYVAL.isEmpty) { S_KEYVAL.append(Character(C_KEYVAL)) }
        
        var result = ""
        for (key, value) in body {
            result += key + S_KEYVAL + value + S_ENTRY
        }
        if (!result.isEmpty) {
            result = String(result.prefix(result.count - 1))
        }
        return result
    }
    
    private func toMediaBytes(image: String) ->  [UInt8] {
        if (image == "null") {
            return [UInt8]()
        }
        if let data = NSData(base64Encoded: image, options: .ignoreUnknownCharacters) {
            var buffer = [UInt8](repeating: 0, count: data.length)
            data.getBytes(&buffer, length: data.length)
            return buffer
        }
        return [UInt8]()
    }
    
    func unpack(data: String) -> Bool {
        var result  = false
        if (S_HEADER.isEmpty) { S_HEADER.append(Character(C_HEADER)) }
        let headers = data.split(separator: Character(C_HEADER), maxSplits: 8, omittingEmptySubsequences: false)
        if (headers.count == 8) {
            mType    = String(headers[0])
            mVersion = String(headers[1])
            mCode    = String(headers[2])
            mStatus  = String(headers[3])
            mPIN     = String(headers[4])
            mL_PIN   = String(headers[5])
            mBodies  = toBodies(data: String(headers[6]))
            mMedia   = toMediaBytes(image: String(headers[7]))
            result   = true
        }
        return result
    }
    
    func unpack(bytes_data: [UInt8]) -> Bool {
        var result  = false
        let data = getData(bytes_data: bytes_data)
        let headers = data.split(separator: Character(C_HEADER), maxSplits: 8, omittingEmptySubsequences: false)
        if (headers.count >= 8) {
            mType    = String(headers[0])
            mVersion = String(headers[1])
            mCode    = String(headers[2])
            mStatus  = String(headers[3])
            mPIN     = String(headers[4])
            mL_PIN   = String(headers[5])
            mBodies  = toBodies(data: String(headers[6]))
            mMedia   = getMedia(bytes_data: bytes_data)
            result   = true
        }
        else {
        }
        return result
    }
    
    private func toBodies(data: String) -> [String: String]  {
        var cvalues = [String: String]()
        
        if (data.isEmpty || data == "") {
            return cvalues
        }
        if (S_ENTRY.isEmpty) { S_ENTRY.append(Character(C_ENTRY)) }
        if (S_KEYVAL.isEmpty) { S_KEYVAL.append(Character(C_KEYVAL)) }
        
        let elements = data.split(separator: Character(C_ENTRY), omittingEmptySubsequences: false)
        
        for element in elements {
            let keyval = element.split(separator: Character(C_KEYVAL), omittingEmptySubsequences: false)
            cvalues[String(keyval[0])] = String(keyval[1])
        }
        return cvalues
    }
    
    private func getData(bytes_data : [UInt8]) -> String {
        var result = ""
        if (S_HEADER.isEmpty) { S_HEADER.append(Character(C_HEADER)) }
        
        var iLength = 0
        for bData in bytes_data {
            let chr = Character(UnicodeScalar(bData))
            
            if (chr == Character(C_HEADER)) {
                iLength = iLength + 1
                if (iLength == 8) {
                    break
                }
            }
            result.append(chr)
        }
        return result
    }
    
    private func getMedia(bytes_data:  [UInt8]) ->  [UInt8] {
        var result:[UInt8] = [UInt8]()
        if bytes_data.count > 0 {
            var ml = getBodyAsInteger(key: MEDIA_LENGTH, default_value: 0)
            if ml == 0 {
                ml = getBodyAsInteger(key: FILE_SIZE, default_value: 0)
            }
            if ml > 0 {
                let start = bytes_data.count - ml
                for index in start...bytes_data.count - 1 {
                    result.append(bytes_data[index])
                }
            }
        }
        return result
    }
    
    func toLogString() -> String {
        var result = ""
        result += ("[" + mType + "]")
        result += ("[" + mVersion + "]")
        result += ("[" + mCode + "]")
        result += ("[" + mStatus + "]")
        result += ("[" + mPIN + "]")
        result += ("[" + mL_PIN + "]")
        result += ("[" + toBodyLogString() + "]")
        result += ("[" + String(mMedia.count) + "]")
        return result
    }
    
    private func toBodyLogString() -> String {
        if (S_ENTRY.isEmpty) { S_ENTRY.append(Character(C_ENTRY)) }
        if (S_KEYVAL.isEmpty) { S_KEYVAL.append(Character(C_KEYVAL)) }
        
        var result = ""
        for (key, value) in mBodies {
            result += "{" + key + "=" + value + "}"
        }
        return result
    }
    
    func isOk() -> Bool {
        return getBody(key: ERRCOD, default_value: "99") == "00"
    }
}

private class CoreMessage_TMessageUtil {
        
    private static var mTID = NSDate().timeIntervalSince1970 * 1000
    
    static func getTID() -> String {
        mTID = Double(Int(mTID) + Int(1))
        return String(Int(mTID))
    }
    
    static func getString(json: Any, key: String) -> String {
        return getString(json: json, key: key, def: "")
    }
    
    static func getString(json: Any, key: String, def: String) -> String {
        if let dict = json as? [String: Any], let value = dict[key] as? String {
            if !value.isEmpty {
                return value
            }
        }
        return def
    }
    
    static func getInt(json: Any, key: String, def: Int) -> Int {
        if let dict = json as? [String: Any], let value = dict[key] as? Int {
            return value
        }
        return def
    }
    
    static func getIntAsString(json: Any, key: String, def: Int) -> String {
        return String(getInt(json: json, key: key, def: def))
    }
    
    static func getLong(json: Any, key: String, def: CLong) -> CLong {
        if let dict = json as? [String: Any], let value = dict[key] as? CLong {
            return value
        }
        return def
    }
    
}

private class SSLibAlertController: UIAlertController {
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        
        // Customize the title's font
        let titleFont = UIFont.boldSystemFont(ofSize: 16)
        let titleAttributes = [NSAttributedString.Key.font: titleFont]
        setValue(NSAttributedString(string: self.title ?? "", attributes: titleAttributes), forKey: "attributedTitle")
        
        // Change the font for the message
        let messageFont = UIFont.systemFont(ofSize: 14)
        let messageAttributes = [NSAttributedString.Key.font: messageFont]
        setValue(NSAttributedString(string: self.message ?? "", attributes: messageAttributes), forKey: "attributedMessage")
        
        for i in self.actions {
            let attributedText = NSAttributedString(string: i.title ?? "", attributes: [NSAttributedString.Key.font : UIFont.systemFont(ofSize: 16)])

            guard let label = (i.value(forKey: "__representer") as AnyObject).value(forKey: "label") as? UILabel else { return }
            label.attributedText = attributedText
        }

    }
}

private class SecureUserDefaultsSS {
    static let shared = SecureUserDefaultsSS()
    private let defaults: UserDefaults
    private let prefsKeyAlias = "_iosx_security_master_key_easysoft_"

    // Initialization with a SymmetricKey
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        do {
            try generateAndStorePrefsKey()
        } catch {
            
        }
    }
    
    func generateAndStorePrefsKey() throws {
        if try isKeyExists(keyAliasCode: prefsKeyAlias) {
            return
        }
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: prefsKeyAlias,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        SecItemDelete(query as CFDictionary) // Remove if it exists
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: nil)
        }
    }
    
    func isKeyExists(keyAliasCode: String) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyAliasCode,
            kSecReturnData as String: false // We only check existence, not retrieve data
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecItemNotFound {
            return false
        } else if status == errSecSuccess {
            return true
        } else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: nil)
        }
    }
    
    func getPrefsKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: prefsKeyAlias,
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: nil)
        }
        
        guard let keyData = item as? Data else {
            throw NSError(domain: "KeyRetrievalError", code: -1, userInfo: nil)
        }
        
        return SymmetricKey(data: keyData)
    }

    func encrypt(data: Data) throws -> Data {
        let key = try getPrefsKey()
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined!
    }
    
    func decrypt(data: Data) throws -> Data {
        let key = try getPrefsKey()
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }

    func set<T: Codable>(_ value: T, forKey key: String) {
        let encoder = JSONEncoder()
        guard let encodedData = try? encoder.encode(value),
              let encryptedData = try? encrypt(data: encodedData) else {
            return
        }
        defaults.set(encryptedData, forKey: key)
    }

    // Retrieve a value
    func value<T: Codable>(forKey key: String) -> T? {
        guard let encryptedData = defaults.data(forKey: key),
              let decryptedData = try? decrypt(data: encryptedData) else {
            return nil
        }
        let decoder = JSONDecoder()
        return try? decoder.decode(T.self, from: decryptedData)
    }

    // Remove a value
    func removeValue(forKey key: String) {
        defaults.removeObject(forKey: key)
    }
    
    func sync() {
        defaults.synchronize()
    }
}

class CallBackSS : CallBack {
    var sID: String = ""
    
    func connectionStateChanged(sUserID: String!, sDeviceID: String!, bConState: Bool!, nConType: Int!, nConSubType: Int!, nCLMConStat: UInt8!) {
        
    }
    
    func gpsStateChanged(nState: Int!) {
        
    }
    
    func sleepStateChanged(bState: Bool!) {
        
    }
    
    func callStateChanged(nState: Int!, sMessage: String!) -> Int {
        return 1
    }
    
    func bcastStateChanged(nState: Int!, sMessage: String!) -> Int {
        return 1
    }
    
    func sshareStateChanged(nState: Int!, sMessage: String!) -> Int {
        return 1
    }
    
    func incomingData(sPacketID: String!, oData: AnyObject!) throws {
        
    }
    
    func lateResponse(sPacketID: String!, sResponse: String!) throws {
        
    }
    
    func asycnACKReceived(sPacketID: String!) throws {
        
    }
    
    func locationUpdated(lTime: Int64!, sLocationInfo: String!) {
        
    }
    
    func resetDB() {
        
    }
    
    
}
