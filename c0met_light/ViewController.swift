//
//  ViewController.swift
//  c0met_light
//
//  Created by Ali on 17.02.2021.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet var ios: UILabel!
    @IBOutlet var imdodel: UILabel!
    @IBOutlet var buttonjb: UIButton!
    @IBOutlet var mm: UIButton!
    let gradient = CAGradientLayer()
       var gradientSet = [[CGColor]]()
       var currentGradient: Int = 0
       
       let gradientOne = UIColor(red: 5/255, green: 40/255, blue: 150/255, alpha: 1).cgColor
       let gradientTwo = UIColor(red: 2/255, green: 50/255, blue: 30/255, alpha: 1).cgColor
       let gradientThree = UIColor(red: 2/255, green: 40/255, blue: 107/255, alpha: 1).cgColor
    override func viewDidAppear(_ animated: Bool) {
            super.viewDidAppear(animated)
            
            gradientSet.append([gradientOne, gradientTwo])
            gradientSet.append([gradientTwo, gradientThree])
            gradientSet.append([gradientThree, gradientOne])
            
            
            gradient.frame = self.view.bounds
            gradient.colors = gradientSet[currentGradient]
            gradient.startPoint = CGPoint(x:0, y:0)
            gradient.endPoint = CGPoint(x:1, y:1)
            gradient.drawsAsynchronously = true
        self.view.layer.insertSublayer(gradient, at:0);
            
            animateGradient()
            
        }
        
        func animateGradient() {
            if currentGradient < gradientSet.count - 1 {
                currentGradient += 1
            } else {
                currentGradient = 0
            }
            
            let gradientChangeAnimation = CABasicAnimation(keyPath: "colors")
            gradientChangeAnimation.duration = 2.0
            gradientChangeAnimation.toValue = gradientSet[currentGradient]
            gradientChangeAnimation.fillMode = CAMediaTimingFillMode.forwards
            gradientChangeAnimation.isRemovedOnCompletion = false
            gradient.add(gradientChangeAnimation, forKey: "colorChange")
        }

    }

    extension ViewController: CAAnimationDelegate {
        func animationDidStop(_ anim: CAAnimation, finished flag: Bool) {
            if flag {
                gradient.colors = gradientSet[currentGradient]
                animateGradient()
            }
        }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        let ioss = UIDevice().systemVersion
    
        let idevice = UIDevice().self.model
        imdodel.self.text=idevice ;
        ios.self.text=ioss;
        
        disable_pt_deny_attach();
        disable_sysctl_debugger_checking();
            
        #if TESTS_BYPASS
        test_aniti_debugger();
        #endif
        


    }
    @IBAction func run_exploit(_ sender: UIButton) {
        let controlStates: Array<UIControl.State> = [.normal, .highlighted, .disabled, .selected, .focused, .application, .reserved]
            for controlState in controlStates {
                buttonjb.setTitle(NSLocalizedString("Ready.", comment: ""), for: controlState)
            }
    
        reloadInputViews();
        
     
        exploit();
        
    }
        func exploit(){
        
            buttonjb.setTitle("bye.", for: .disabled);
            let task_pack = cicuta_virosa();
           
            if(disable_sandbox(task_pack)==1){
                let alert = UIAlertController(title: "c0m@jb", message: "Jailbreak was Successfull\npatched permissions\npatched off_sandbox_slot\nInstalled Bootstrap Data", preferredStyle: UIAlertController.Style.alert)
                alert.addAction(UIAlertAction(title: "Ok", style: UIAlertAction.Style.default, handler: nil))
                self.present(alert, animated: true, completion: nil)
            }
            if(task_pack==70896){
                let alert = UIAlertController(title: "c0m@ - exploit", message: "task_port returned 0x0\nyou should try again.", preferredStyle: UIAlertController.Style.alert)
                alert.addAction(UIAlertAction(title: "Ok", style: UIAlertAction.Style.default, handler: nil))
                self.present(alert, animated: true, completion: nil)
         
            }
        }
    

}

