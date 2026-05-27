// frontend/src/components/ParallaxBg.jsx
import { useEffect, useRef } from 'react'

export default function ParallaxBg() {
  const ring1Ref  = useRef(null)
  const ring2Ref  = useRef(null)
  const ring3Ref  = useRef(null)
  const gridRef   = useRef(null)

  useEffect(() => {
    let nx = 0, ny = 0, tx = 0, ty = 0, raf

    const onMouse = (e) => {
      tx = e.clientX / window.innerWidth  - 0.5
      ty = e.clientY / window.innerHeight - 0.5
    }

    const tick = () => {
      nx += (tx - nx) * 0.05
      ny += (ty - ny) * 0.05

      const apply = (el, factor) => {
        if (!el) return
        const ox = (nx * factor).toFixed(2)
        const oy = (ny * factor).toFixed(2)
        el.style.transform = `translate(calc(-50% + ${ox}px), calc(-50% + ${oy}px))`
      }

      apply(ring1Ref.current,  18)
      apply(ring2Ref.current,  36)
      apply(ring3Ref.current,  54)

      if (gridRef.current) {
        gridRef.current.style.transform =
          `translate(${(nx * 14).toFixed(2)}px, ${(ny * 10).toFixed(2)}px)`
      }

      raf = requestAnimationFrame(tick)
    }

    window.addEventListener('mousemove', onMouse)
    raf = requestAnimationFrame(tick)
    return () => {
      window.removeEventListener('mousemove', onMouse)
      cancelAnimationFrame(raf)
    }
  }, [])

  return (
    <div className="parallax-bg">
      <div ref={gridRef}  className="grid-lines" />
      <div ref={ring1Ref} className="orbit orbit-1" />
      <div ref={ring2Ref} className="orbit orbit-2" />
      <div ref={ring3Ref} className="orbit orbit-3" />
    </div>
  )
}
