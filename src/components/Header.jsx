import PNBShield from './PNBShield.jsx'
import { Bell, Star } from 'lucide-react'

export default function Header() {
  const now = new Date()
  const dateStr = now.toLocaleDateString('en-IN', {
    day: '2-digit', month: '2-digit', year: 'numeric'
  })

  return (
    <header className="h-20 bg-white/90 backdrop-blur-sm border-b border-amber-200 flex items-center justify-between px-6 shadow-sm flex-shrink-0">
      {/* Date */}
      <span className="font-display text-sm text-pnb-crimson font-semibold tracking-wide">
        {dateStr}
      </span>

      {/* Centre — Logo + Title */}
      <div className="flex items-center gap-3">
        <PNBShield size={52} />
        <div className="text-center">
          <p className="font-display text-xs text-pnb-crimson tracking-widest uppercase opacity-70">
            PSB Hackathon 2026
          </p>
        </div>
      </div>

      {/* Right — User + alerts */}
      <div className="flex items-center gap-4">
        <button className="relative p-2 rounded-full hover:bg-amber-50 transition-colors">
          <Bell size={18} className="text-pnb-crimson" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full badge-critical" />
        </button>
        <div className="flex items-center gap-2 bg-amber-50 border border-amber-200 rounded-full px-4 py-1.5">
          <div className="w-7 h-7 rounded-full bg-pnb-crimson flex items-center justify-center">
            <Star size={12} className="text-amber-300" fill="currentColor" />
          </div>
          <span className="font-display text-sm text-pnb-crimson font-semibold">
            Welcome, hackathon_user..!
          </span>
        </div>
      </div>
    </header>
  )
}
