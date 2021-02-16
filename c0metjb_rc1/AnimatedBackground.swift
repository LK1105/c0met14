//
//  AnimatedBackground.swift
//  c0metjb_rc1
//
//  Created by Mattso on 16/02/2021.
//

import SwiftUI
import UIKit

struct ContentView: View {
    var body: some View {
        AnimatedBackground().edgesIgnoringSafeArea(/*@START_MENU_TOKEN@*/.all/*@END_MENU_TOKEN@*/)
            .blur(radius: 50)
    }
}

struct AnimatedBackground: View {
    @State var start  = UnitPoint(x: 0, y: -2)
    @State var end = UnitPoint(x: 4, y: 0)
    
    let timer = Timer.publish(every: 1, on: .main, in: .default).autoconnect()
    let colors = [Color.blue, Color.purple]
    
    var body: some View {
        LinearGradient(gradient: Gradient(colors: [Color.red, Color.blue]), startPoint: start, endPoint: end)
            .animation(Animation.easeInOut(duration: 6)
                        .repeatForever()
            ).onReceive(timer, perform: { _ in
                self.start = UnitPoint(x: 4, y: 0)
                self.end = UnitPoint(x: 0, y: 2)
                self.start = UnitPoint(x: -4, y: 20)
                self.start = UnitPoint(x: 4, y: 0)
            })
    }
}

struct AnimatedBackground_Previews: PreviewProvider {
    static var previews: some View {
        AnimatedBackground()
    }
}

class AnimationHostingController: UIHostingController<ContentView> {

    required init?(coder: NSCoder) {
        super.init(coder: coder,rootView: ContentView());
    }

    override func viewDidLoad() {
        super.viewDidLoad()
    }
}
